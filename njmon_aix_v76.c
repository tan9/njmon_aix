/*
    njmon / nimon -- collects AIX performance data and generates JSON or 
			InfluxDB Line Protocol format data.
    Developer: Nigel Griffiths.
    (C) Copyright 2018 Nigel Griffiths

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    Find the GNU General Public License here <http://www.gnu.org/licenses/>.

    Data in the perfstat library not collected and why
    - tape total = already collect individual tapes & not expecting many tapes
    - bio dev = tried this but "No bio device found." 
    - thread = too many threads and low value
    - WPAR various stats - wait for user demand as its adds to many stats
    - diskpath = SAN multi-path MPIO rather a lot of data
 
    Compiling xlc or gcc are fine 
    See Makefile for compile details and ninstall installation
    From v76 njmon and nimon are the same binary file

    Explanation of #ifdef
    #ifdef AIX6  AIX has a two missing stats compared to AIX7. Also needed for VIOS 2.2
    #ifdef VIOS  added -v vhost (virtual adapter) and virtual disk target
    #ifdef SSP   added -u and -U includes Shared Storage Pool stats in 
     VIOS 2.2 compile on AIX61 TL9 sp11+
     VIOS 3.1 compile on AIX7.2 TL3+
*/
#ifdef AIX6
char njmon_version[] =  "njmon4AIX6-v76-16/05/2021";
#else /* AIX 7 */
char njmon_version[] =  "njmon4AIX7-v76-16/05/2021";
#endif /* AIX6 */

#define NJMON 6
#define NIMON 42
#define NSMON 99

int mode = NJMON;

char    *njmon_command;

/* Work around an AIX bug in oslevel -s */
int    rpm_stuck = 0;

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <libperfstat.h>
#include <ctype.h>
#include <signal.h>
#include <pwd.h>
#include <time.h>
#include <string.h>
#include <strings.h>
#include <mntent.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <sys/vminfo.h>
#include <sys/time.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/vfs.h>
#include <fcntl.h> /* for flesystems */
#include <fstab.h>
#include <math.h>
#include <float.h>
#include <sys/statfs.h>
#include <sys/systemcfg.h>
#include <netinet/in.h> /* below includes are for socket handling */
#include <arpa/inet.h>
#include <sys/proc.h>   /* for loadavg SBITS */

#define FUNCTION_START if(debug)fprintf(stderr,"%s called line %d\n",__func__, __LINE__);
#define DEBUG if(debug)
#define FLUSH   if(debug) fflush(NULL);

/* global scope variables */
long   loop;
char   filename_ff2[64];
int    sockfd = 1;   /*default is stdout, only changed if we are using a remote socket */
int    debug = 0;
int    verbose = 0;
int    warnings = 1;
int    danger = 0;  /* skip libperfstat function that fail badly */
int    elastic = 0;
int    file_output   = 0;
int    oracle = 0;

double    nominal_mhz = 1;
double    current_mhz = 2;

char    hostname[1024];
char    fullhostname[1024];
int	fullhostname_tag = 0;

char    saved_serial_no[9];
char    saved_lpar_num_name[31];
char    saved_machine_type[31];
char    saved_uname_node[31];

char	target_host[1024 + 1] = { 0 };
char    target_ip[64+1];
long    target_port = 0;

void    nwarning( char *buf)
{
    if(warnings) {
	fprintf(stderr, "WARNING:njmon: %s\n", buf);
	if(errno != 0)
		fprintf(stderr, "WARNING:njmon: %s errno=%d: %s\n", buf, errno, sys_errlist[errno]);
	else
		fprintf(stderr, "WARNING:njmon: %s\n", buf);
    }
}

void nwarningd( char *s1, long long i)
{
char	msgbuf[1024];

	sprintf(msgbuf, s1, i);
	nwarning(msgbuf);
}

void nwarning2( char *s1, char *s2)
{
char	msgbuf[1024];

	sprintf(msgbuf, s1, s2);
	nwarning(msgbuf);
}

void    nerror( char *buf)
{
    if(errno != 0)
	fprintf(stderr, "ERROR:njmon: %s errno=%d: %s\n", buf, errno, sys_errlist[errno]);
    else
	fprintf(stderr, "ERROR:njmon: %s\n", buf);
    exit(1);
}


void    interrupt(int signum)
{
    switch (signum) {
    case SIGUSR1:
    case SIGUSR2:
        fflush(NULL);
        close(sockfd); /* may help the other end close down */
        sleep(1);
        exit(0);
        break;
    }
}

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

int    create_socket()
{
    int    i;
    static struct sockaddr_in serv_addr;

    DEBUG fprintf(stderr, "socket: trying to connect to \"%s\":%d\n", target_ip, target_port);
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        nerror("njmon:socket() call failed");
	return 0;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(target_ip);
    serv_addr.sin_port = htons(target_port);

    /* Connect tot he socket offered by the web server */
    if (connect(sockfd, (struct sockaddr *) & serv_addr, sizeof(serv_addr)) < 0) {
        DEBUG nwarning("njmon: connect() call failed\n");
        return 0;
    }
    return 1;
}


/* Output buffering to ensure single write and allow EOL comma removal */
#define INITIAL_BUFFER_SIZE (1024 * 1024) /* 64 MB */

char    *output;
long    output_size = 0;
long    output_char = 0;

void    buffer_check()
{
    long    size;
    if ( output_char > (long)(output_size * 0.95) ) { /* within 5% of the end */
        size = output_size + (1024 * 1024); /* add another MB */
        output = realloc((void *)output, size);
        output_size = size;
    }
}


void    remove_ending_comma_if_any()
{
    if (output[output_char -1] == ',') {
        output[output_char -1] = 0; /* remove the char */
        output_char--;
    }
}


/* collect stats on the metrix */
int    njmon_internal_stats = 0;
int    njmon_sections = 0;
int    njmon_subsections = 0;
int    njmon_string = 0;
int    njmon_long = 0;
int    njmon_double = 0;
int    njmon_hex = 0;

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
*
* NIMON mode p functions to generate InfluxDB Line Protocol output
*    the Line Protocol is appended to the buffer "output" so
* NJMON mode p functions to generate JSON output
*    the JSON is appended to the buffer "output" so
*        we can remove the trailing "," before we close the entry with a "}"
*
* Both write the whole record in a single write (push()) to help down stream tools
*
*    psection(name) and psectionend()
*
*    psub(name) and psubend()
*       similar to psection/psectionend but one level deeper
*       example
*           "disks": { 
* 		{"name": "hdisk0", "size": 400, "reads": 123.2, ...... }
*           }
*
*    pstring(name,"abc")
*    plong(name, 1234)
*    pdouble(name, 1234.546)
*    phex(name, hedadecimal number)
*    praw(name) for other stuff requires raw pre-format string like "name": data,
*
 - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

void    praw(char *string)
{
    output_char += sprintf(&output[output_char], "%s", string);
}

void    replace_curly_with_square()
{
    if (output[output_char -1] == '{') {
        output[output_char -1] = '[';
    }
}

int    psubended = 0; /* stop psubend and psectionend both enig the measure */
int    first_sub = 0; /* need to remove the psection measure before adding psub measure */

/* the Influx login details */
char    influx_database[64];
char    influx_username[64];
char    influx_password[64];

int     telegraf_mode = 0;

char    *saved_arch;

void    save_arch(char *arch)
{
    DEBUG fprintf(stderr, "SAVE arch=|%s|\n", arch);
    saved_arch = malloc(strlen(arch) + 1);
    strcpy(saved_arch, arch);
}

char    saved_section[64];
char    saved_sub[64];

void    psample()
{
    if(mode == NJMON)
	praw("{"); /* start of sample */
}

/* extra tags to allow Grafana GroupBy for virtual FC adapter client name and network type */
char    saved_tag[256];

void    psampleend() 
{ 
    if(mode == NJMON) {
	remove_ending_comma_if_any();
	praw("}\n");
    }
}

void    psection(char *section)
{
    char *h;

    buffer_check();
    if(mode == NJMON ){
	    buffer_check();
	    njmon_sections++;
	    output_char += sprintf(&output[output_char], "\"%s\": {", section);
    } else {
	    njmon_sections++;
	    if (fullhostname_tag)
		h = fullhostname; 
	    else
		h = hostname; 
	    output_char += sprintf(&output[output_char], "%s,host=%s,os=AIX,architecture=%s,serial_no=%s,mtm=%s ",
		section, h, saved_arch, saved_serial_no, saved_machine_type);
	    strcpy(saved_section, section);
	    first_sub = 1;
	    psubended = 0;
    }
}


void    psubtag(char *tag)
{
    strcpy(saved_tag, tag);
}

int    sub_array = 0;

void    psub(char *resource)
{
    int    i;
    char  *h;

    if(mode == NJMON) {
	    buffer_check();
	    njmon_subsections++;
	    if (elastic) {
		replace_curly_with_square();
		output_char += sprintf(&output[output_char], "{ \"item\": \"%s\",", resource);
		sub_array = 1;
	    } else {
		output_char += sprintf(&output[output_char], "\"%s\": {", resource);
	    }

    } else {
	    buffer_check();
	    njmon_subsections++;

	    /* remove section */
	    if (first_sub) {
		for (i = output_char - 1; i > 0; i--) {
		    if (output[i] == '\n') {
			output[i+1] = 0;
			output_char = i + 1;
			break;
		    }
		}
	    }
	    first_sub = 0;

	    /* remove the trailing s */
	    strcpy(saved_sub, saved_section);

	    if(!strcmp("processes", saved_sub)) {
		strcpy(saved_sub,"process");
	    } else {
		if (saved_sub[strlen(saved_sub) - 1] == 's') {
		    saved_sub[strlen(saved_sub) - 1] = 0;
		}
	    }
	    if(fullhostname_tag)
		h = fullhostname;
	    else
		h = hostname;
	    output_char += sprintf(&output[output_char], "%s,host=%s,os=AIX,architecture=%s,serial_no=%s,mtm=%s,%s_name=%s%s ",
			    saved_section, h, saved_arch, saved_serial_no, saved_machine_type, saved_sub, resource, saved_tag);
	    psubended = 0;
    }
}


void    psubend()
{
    if(mode == NJMON) {
	    remove_ending_comma_if_any();
	    praw("},");
    } else {
	    remove_ending_comma_if_any();
	    if(file_output >= 2) 
		output_char += sprintf(&output[output_char], " %ld000000000\n", (long)time(0));
	    else
		output_char += sprintf(&output[output_char], "   \n");
	    saved_tag[0] = 0; /* remove sub tag */
	    psubended = 1;
    }
}


void    psectionend()
{
    remove_ending_comma_if_any();
    if(mode == NJMON) {
	    if (sub_array)
		praw("],");
	    else
		praw("},");
	    sub_array = 0;
    } else {
	if (!psubended) {
	    if(file_output >= 2) 
	    	output_char += sprintf(&output[output_char], " %ld000000000\n", (long)time(0));
	    else
	        output_char += sprintf(&output[output_char], "   \n");
	}
	psubended = 0;
    }
}


void    phex(char *name, long long value)
{
    if(mode == NJMON ) {
	njmon_hex++;
	output_char += sprintf(&output[output_char], "\"%s\": \"0x%08llx\",", name, value);
    } else {
	njmon_hex++;
	output_char += sprintf(&output[output_char], "%s=\"0x%08llx\",", name, value);
    }
}


void    plong(char *name, long long value)
{
    if(mode == NJMON) {
	    njmon_long++;
	    output_char += sprintf(&output[output_char], "\"%s\": %lld,", name, value);
	    DEBUG fprintf(stderr,"plong(%s,%lld) count=%ld\n", name, value, output_char);
    } else {
	    njmon_long++;
	    output_char += sprintf(&output[output_char], "%s=%lldi,", name, value);
    }
}


void    pdouble(char *name, double value)
{
    if(mode == NJMON) {
	    njmon_double++;
	    if ( isnan(value) || isinf(value) ) { /* Not-a-number or infinity */
		DEBUG  printf("pdouble(%s,%.1f) - NaN error\n", name, value);
	    } else {
		output_char += sprintf(&output[output_char], "\"%s\": %.3f,", name, value);
		DEBUG fprintf(stderr,"pdouble(%s,%.1f) count=%ld\n", name, value, output_char);
	    }
    } else {
	    njmon_double++;
	    if ( isnan(value) || isinf(value) ) { /* Not-a-number or infinity */
		DEBUG fprintf(stderr, "pdouble(%s,%.1f) - NaN error\n", name, value);
	    } else {
		output_char += sprintf(&output[output_char], "%s=%.3f,", name, value);
		DEBUG fprintf(stderr, "pdouble(%s,%.1f) count=%ld\n", name, value, output_char);
	    }
    }
}


void    pstring(char *name, char *value)
{
    int    i;
    int    len;
    if(mode == NJMON) {
	    buffer_check();
	    njmon_string++;
	    len = strlen(value);
	    for (i = 0; i < len; i++)
		if ( value[i] == '\n' || iscntrl(value[i]))
		    value[i] = ' ';
	    output_char += sprintf(&output[output_char], "\"%s\": \"%s\",", name, value);
	    DEBUG fprintf(stderr,"pstring(%s,%s) count=%ld\n", name, value, output_char);
    } else {
	    buffer_check();
	    njmon_string++;
	    len = strlen(value);
	    for (i = 0; i < len; i++)
		if ( value[i] == '\n' || iscntrl(value[i]))
		    value[i] = ' ';
	    output_char += sprintf(&output[output_char], "%s=\"%s\",", name, value);
	    DEBUG fprintf(stderr, "pstring(%s,%s) count=%ld\n", name, value, output_char);
    }
}


void    push()
{
    char    header[1024];
    char    result[1024];
    char    buffer[1024*8];
    int    ret;
    int    i;
    int    total;
    int    sent;
    int    code;
    char   filename[64];
    int    outfile;

    FUNCTION_START;
    if(mode == NJMON) {
	    buffer_check();
	    if ( output_char == 0) /* noting to send so skip this operation */
		return;
	    if (target_port) {
		DEBUG fprintf(stderr,"push() size=%ld\n", output_char);
		if ( create_socket() == 1 ) {
		    if ( write(sockfd, output, output_char) < 0) {
			/* if socket failed there is not much we can do but carry on */
			nwarning("njmon write to stdout failed, stopping now.");
		    }
		    fflush(NULL);  /* force I/O output now */
		    close(sockfd);
		    DEBUG fprintf(stderr,"push complete\n");
		} else
		    DEBUG fprintf(stderr,"socket create failed\n");
	    } else {
	        if(file_output >= 2) { /* -ff mode open ned file in the series */
                    sprintf( filename, "%s_%06d.json", filename_ff2, loop); 
        	    if( (outfile = open(filename,  O_WRONLY | O_CREAT)) == -1 ) {
            	        nwarning2("opening file filename=%s\n", filename);
            	        exit(33333);
            	    }
		    if ( write(outfile, output, output_char) < 0) {
		        /* if stdout failed there is not much we can do hopefully more disk space next time */
		        nwarning("njmon write to stdout failed, stopping now.");
	    	    }
		    close(outfile);
	        } else { 
		    if ( write(sockfd, output, output_char) < 0) {
		        /* if stdout failed there is not much we can do hopefully more disk space next time */
		        nwarning("njmon write to stdout failed, stopping now.");
	    	    }
		}
		fflush(NULL);  /* force I/O output now */
	    }
    } else {
	    buffer_check();
	    if ( output_char == 0) /* noting to send so skip this operation */
		return;
	    if (target_port) {
		DEBUG fprintf(stderr, "push() size=%ld\n", output_char);
		if ( create_socket() == 1 ) {

		    if(!telegraf_mode) {
			sprintf(buffer, "POST /write?db=%s&u=%s&p=%s HTTP/1.1\r\nHost: %s:%d\r\nContent-Length: %ld\r\n\r\n",
			   influx_database, influx_username, influx_password, target_host, target_port, output_char);
			DEBUG fprintf(stderr, "POST size=%d buffer=<%s>\n", strlen(buffer), buffer);
			if (verbose) 
			   DEBUG fprintf(stderr, "buffer size=%d buffer=<%s>\n", strlen(buffer), buffer);
			if ( (ret = write(sockfd, buffer, strlen(buffer))) != strlen(buffer)) {
			 nwarning("njmon write POST to sockfd failed.");
			}
		    }
		    total = output_char;
		    sent = 0;
		    if (verbose) 
			fprintf(stderr, "output size=%d output=\n<%s>\n", total, output);
		    while ( sent < total) {
			ret = write(sockfd, &output[sent], total - sent);
			if (verbose) 
			    fprintf(stderr, "Written=%d bytes sent=%d total=%d\n", ret, sent, total);
			if (ret < 0) {
			    nwarning("njmon write body to sockfd failed.");
			    break;
			}
			sent = sent + ret;
		    }
		    for (i = 0; i < 1024; i++)
			result[i] = 0;
		    if ( (ret = read(sockfd, result, sizeof(result))) > 0) {
			result[ret] = 0;
			if (verbose) 
			    fprintf(stderr, "received bytes=%d data=<%s>\n", ret, result);
			/* ------> */
			sscanf(result, "HTTP/1.1 %d", &code);
			for (i = 13; i < 1024; i++)
			    if (result[i] == '\r')
				result[i] = 0;
			if (verbose) fprintf(stderr, "HTTP Code=%d Text=%s\n", code, &result[13]);
			if (code != 204)
			    if (verbose) fprintf(stderr, "-->%s<--\n", result);
		    }
		    close(sockfd);
		    sockfd = 0;
		    if (verbose) fprintf(stderr, "push complete\n");
		} else {
		    if (debug || verbose) fprintf(stderr, "socket create failed\n");
		}
	    } else {
		/* save to local file */
		if ( write(1, output, output_char) < 0) {
		    /* if stdout failed there is not much we can do hopefully more disk space next time */
		    if (verbose) fprintf(stderr, "file output failed\n");
		    nerror("njmon write to stdout failed, stopping now.");
		}
		fflush(NULL);  /* force I/O output now */

	    }
    }
    output[0] = 0;
    output_char = 0;
}


void    pstats()
{
    psection("njmon_internal_stats");
    plong("section",    njmon_sections);
    plong("subsections", njmon_subsections);
    plong("string",     njmon_string);
    plong("long",       njmon_long);
    plong("double",     njmon_double);
    plong("hex",        njmon_hex);
    psectionend("njmon_internal_stats");
}


void    remove_nl(char *string)
{
    int    len;

    len = strlen(string);
    if (string[len - 1] == '\n') /* Remove NL */
        string[len - 1] = 0;
}


#define RETURN 400
#define EXIT 402
#define DUMP 404

void    assert(const unsigned char *file, 
		const unsigned char *function,
		const unsigned int line, 
		const unsigned char *expression,
		char *reason, 
		int next,
		int flag,
		long long value,
		void *ptr)
{
    int    *c;

    if(next == RETURN && !warnings)
	return;		/* Ignore non-fatal assert errors */

    fprintf(stderr, "ERROR: njmon version %s\n", njmon_version);
    fprintf(stderr, "ERROR: Assert Failure in file=\"%s\" in function=\"%s\" at line=%d\n", file, function, line);
    fprintf(stderr, "ERROR: Reason=%s\n", reason);
    if (flag)
        fprintf(stderr, "ERROR: Pointer=0x%x\n", (char *)ptr);
    else
        fprintf(stderr, "ERROR: Value=%lld\n", value);
    fprintf(stderr, "ERROR: Expression=[[%s]]\n", expression);
    if (errno != 0) {
        fprintf(stderr, "ERROR: errno=%d\n", errno);
        perror("ERROR: errno means ");
    }
    switch (next) {
    case RETURN:
        fprintf(stderr, "ERROR: Switching off these stats and continuing\n");
        return;
    case EXIT:
        fprintf(stderr, "ERROR: Exiting njmon\n");
        exit(666);
    case DUMP:
        fprintf(stderr, "ERROR: Forcing an njmon core dump\n");
        c = NULL;
        *c = 42;
        /* should never get here */
    }
    /* should never get here */
}


#define ASSERT(expression, reason, next, value)     { \
    if(debug) \
        printf("ASSERT CHECK: %s %s %d %s %s %d %ld\n",  __FILE__, __func__, __LINE__, "expression", reason, next, (long long)value); \
    if( !(expression) ) \
    assert( __FILE__, __func__, __LINE__, "expression", reason, next, 0, (long long)value, NULL); }

#define ASSERT_PTR(expression, reason, next, ptr)     { \
    if(debug) \
        printf("ASSERT CHECK: %s %s %d %s %s %d %ld\n",  __FILE__, __func__, __LINE__, "expression", reason, next, (void *)ptr); \
    if( !(expression) ) \
    assert( __FILE__, __func__, __LINE__, "expression", reason, next, 1, 0, ptr); }


int    first_time = 1;
int    aix_version = 0;      /* which AIX version */
int    aix_tl = 0;
int    aix_sp = 0;
int    aix_year = 0;
int    aix_week = 0;

void    aix_server_init()
{
    FILE * pop;
    char    string[4096];
    int    i;
    char    oslevel_command[256];

    FUNCTION_START;

    if (rpm_stuck)
        strcpy(oslevel_command, "oslevel >2>/dev/null");
    else
        strcpy(oslevel_command, "oslevel -s >2>/dev/null");

    if ( (pop = popen("oslevel -s 2>/dev/null", "r") ) != NULL ) {
        if ( fgets(string, 256, pop) != NULL) {
            if (rpm_stuck) {
                /* 7.2.0.0 */
                sscanf(string, "%d.%d", &aix_version, &aix_tl);
            } else {
                /* 7200-01-01-1642 */
                sscanf(string, "%d-%d-%d-%2d%2d", &aix_version, &aix_tl, &aix_sp, &aix_year, &aix_week);
            }
        }
        pclose(pop);
    } else {
        ASSERT_PTR(pop == NULL, "oslevel -s", RETURN, pop);
    }

    /* serial number */
    if ( (pop = popen("uname -u 2>/dev/null", "r") ) != NULL ) {
        if ( fgets(string, 256, pop) != NULL) {
            strncpy(saved_serial_no, &string[6], 8);
        }
        pclose(pop);
        remove_nl(saved_serial_no);
    } else {
        strcpy(saved_serial_no, "none");
        ASSERT_PTR(pop == NULL, "uname -u(serial no)", RETURN, pop);
    }

    /* LPAR Number Name like "17 myLPAR" */
    if ( (pop = popen("uname -L 2>/dev/null", "r") ) != NULL ) {
        if ( fgets(string, 256, pop) != NULL) {
            strncpy(saved_lpar_num_name, &string[0], 30);
        }
        pclose(pop);
        if ( saved_lpar_num_name[0] == '-' && saved_lpar_num_name[1] == '1')
            strcpy(saved_lpar_num_name, "notset");

        if ( saved_lpar_num_name[0] == '1' && saved_lpar_num_name[1] == ' ' && 
            saved_lpar_num_name[2] == 'N' && saved_lpar_num_name[3] == 'U' && 
            saved_lpar_num_name[4] == 'L' && saved_lpar_num_name[5] == 'L'  )
            strcpy(saved_lpar_num_name, "NULL");

        for (i = 0; i < 4; i++) {       /* change to comma seperated */
            if (saved_lpar_num_name[i] == ' ') {
                saved_lpar_num_name[i] = ',';
                break;
            }
        }
        remove_nl(saved_lpar_num_name);
    } else {
        strcpy(saved_lpar_num_name, "none");
        ASSERT_PTR(pop == NULL, "uname -L(lpar no & name)", RETURN, pop);
    }

    /* Machine type */
    if ( (pop = popen("uname -M 2>/dev/null", "r") ) != NULL ) {
        if ( fgets(string, 256, pop) != NULL) {
            strncpy(saved_machine_type, &string[0], 30);
        }
        pclose(pop);
        remove_nl(saved_machine_type);
        for (i = 0; i < strlen(saved_machine_type); i++)
            if (saved_machine_type[i] == ',')
                saved_machine_type[i] = '-';

    } else {
        strcpy(saved_machine_type, "unknown");
        ASSERT_PTR(pop == NULL, "uname -M(machine-type)", RETURN, pop);
    }

    /* Node */
    if ( (pop = popen("uname -n 2>/dev/null", "r") ) != NULL ) {
        if ( fgets(string, 256, pop) != NULL) {
            strncpy(saved_uname_node, &string[0], 30);
        }
        pclose(pop);
        remove_nl(saved_uname_node);
    } else {
        strcpy(saved_uname_node, "unknown");
        ASSERT_PTR(pop == NULL, "uname -n (node)", RETURN, pop);
    }
}

long error_count = 0;

long logged_errors()
{
    long i;
    char string[4096];
    FILE * pop;

    if ( (pop = popen("/usr/bin/errpt 2>/dev/null", "r") ) != NULL ) {
        for(i=0; ;i++) {
            if ( fgets(string, 4095, pop) == NULL)  {
                break;
            }
        }
        pclose(pop);
        i--;
        if(i < 0)
            i = 0;
        return i;
    }
}


void    aix_server()
{

    psection("server");
    pdouble("aix_version", (double)aix_version / 1000.0);
    plong("aix_technology_level",     aix_tl);
    plong("aix_service_pack",     aix_sp);
    plong("aix_build_year",         2000 + aix_year);
    plong("aix_build_week",         aix_week);
    pstring("serial_no",         saved_serial_no);
    pstring("lpar_number_name",     saved_lpar_num_name);
    pstring("machine_type",         saved_machine_type);
    pstring("uname_node",         saved_uname_node);
    plong("errpt_errors",         logged_errors());
    psectionend();
}


time_t timer;       /* used to work out the time details*/
struct tm *tim;     /* used to work out the local hour/min/second */

void    get_time()
{

    timer = time(0);
}


void    get_localtime()
{
    tim = localtime(&timer);
    tim->tm_year += 1900;    /* read localtime() manual page! */
    tim->tm_mon += 1;    /* because it is 0 to 11 */
}


/* UTC is best to use as its time zone indepentant */
void    get_utc()
{
    tim = gmtime(&timer);
    tim->tm_year += 1900;  /* read gmtime() manual page! */
    tim->tm_mon += 1;      /* because it is 0 to 11 */
}


void    date_time(long seconds, long loop, long maxloops, double sleeping, double sleep_overrun, double execute_time, double elapsed)
{
    char    buffer[256];

    /* This is ISO 8601 datatime string format - ughly but get over it! :-) */
    get_time();
    get_localtime();
    psection("timestamp");
    sprintf(buffer, "%04d-%02d-%02dT%02d:%02d:%02d",
        tim->tm_year,
        tim->tm_mon,
        tim->tm_mday,
        tim->tm_hour,
        tim->tm_min,
        tim->tm_sec);
    pstring("datetime", buffer);
    get_utc();
    sprintf(buffer, "%04d-%02d-%02dT%02d:%02d:%02d",
        tim->tm_year,
        tim->tm_mon,
        tim->tm_mday,
        tim->tm_hour,
        tim->tm_min,
        tim->tm_sec);
    pstring("UTC", buffer);
    plong("snapshot_seconds", seconds);
    plong("snapshot_maxloops", maxloops);
    plong("snapshot_loop", loop);
    pdouble("sleeping", sleeping);
    pdouble("execute_time",  execute_time);
    pdouble("sleep_overrun", sleep_overrun);
    pdouble("elapsed", elapsed);

    plong("Xint",  (long long)_system_configuration.Xint );
    plong("Xfrac", (long long)_system_configuration.Xfrac);
    psectionend();
}


/* - - - - - NFS - - - - */
int    nfs_on = 1;
int    nfs_2_server = 1;
int    nfs_2_client = 1;
int    nfs_3_server = 1;
int    nfs_3_client = 1;
int    nfs_4_server = 1;
int    nfs_4_client = 1;

#define NFS_TOTALS  0
#define NFS_VERSION_2 1
#define NFS_VERSION_3 2
#define NFS_VERSION_4 3

perfstat_protocol_t     *nfsp; /* The previous and current pointers */
perfstat_protocol_t     *nfsq;

void    ps_nfs_init()
{
    int    rc;
    perfstat_id_t perfid;

    if (nfs_on) {
        nfsp = malloc(sizeof(perfstat_protocol_t) * 4);
        nfsq = malloc(sizeof(perfstat_protocol_t) * 4);

        strcpy(perfid.name, "nfs");
        rc = perfstat_protocol(&perfid, &nfsp[0], sizeof(perfstat_protocol_t), 4);
        ASSERT(rc > 0, "perfstat_protocol(nfs init)", RETURN, rc);
        if (rc <= 0) {
            nfs_on = 0;
            return;
        }
        memcpy(&nfsq[0], &nfsp[0], sizeof(perfstat_protocol_t) * 4);
    }
}


void    ps_nfs(double elapsed)
{
    int    rc;
    static perfstat_id_t perfid;
    perfstat_protocol_t     * temp;

    if (!nfs_on)
        return;

    /* Switch pointers over */
    temp = nfsp;
    nfsp = nfsq;
    nfsq = temp;

    strcpy(perfid.name, "nfs");
    rc = perfstat_protocol(&perfid, &nfsp[NFS_TOTALS], sizeof(perfstat_protocol_t), 1);
    ASSERT(rc > 0, "perfstat_protocol(nfs totals)", RETURN, rc);
    if (rc <= 0) {
        nfs_on = 0;
        return;
    }

    if (nfs_2_client || nfs_2_server) {
        strcpy(perfid.name, "nfsv2");
        rc = perfstat_protocol(&perfid, &nfsp[NFS_VERSION_2], sizeof(perfstat_protocol_t), 1);
        ASSERT(rc > 0, "perfstat_protocol(nfs v2)", RETURN, rc);
        if (rc <= 0) {
            nfs_2_client = nfs_2_server  = 0;
            return;
        }
    }

    if (nfs_3_client || nfs_3_server) {
        strcpy(perfid.name, "nfsv3");
        rc = perfstat_protocol(&perfid, &nfsp[NFS_VERSION_3], sizeof(perfstat_protocol_t), 1);
        ASSERT(rc > 0, "perfstat_protocol(nfs v3)", RETURN, rc);
        if (rc <= 0) {
            nfs_3_client = nfs_3_server  = 0;
            return;
        }
    }

    if (nfs_4_client || nfs_4_server) {
        strcpy(perfid.name, "nfsv4");
        rc = perfstat_protocol(&perfid, &nfsp[NFS_VERSION_4], sizeof(perfstat_protocol_t), 1);
        ASSERT(rc > 0, "perfstat_protocol(nfs v4)", RETURN, rc);
        if (rc <= 0) {
            nfs_4_client = nfs_4_server  = 0;
            return;
        }
    }

#define nfs(type,member) pdouble(#type "_" #member, (double)(nfsp[NFS_TOTALS].u.nfs.type.member - nfsq[NFS_TOTALS].u.nfs.type.member)/elapsed)

#define nfs2s(member) pdouble(#member, (double)(nfsp[NFS_VERSION_2].u.nfsv2.server.member - nfsq[NFS_VERSION_2].u.nfsv2.server.member)/elapsed)
#define nfs2c(member) pdouble(#member, (double)(nfsp[NFS_VERSION_2].u.nfsv2.client.member - nfsq[NFS_VERSION_2].u.nfsv2.client.member)/elapsed)

#define nfs3s(member) pdouble(#member, (double)(nfsp[NFS_VERSION_3].u.nfsv3.server.member - nfsq[NFS_VERSION_3].u.nfsv3.server.member)/elapsed)
#define nfs3c(member) pdouble(#member, (double)(nfsp[NFS_VERSION_3].u.nfsv3.client.member - nfsq[NFS_VERSION_3].u.nfsv3.client.member)/elapsed)

#define nfs4s(member) pdouble(#member, (double)(nfsp[NFS_VERSION_4].u.nfsv4.server.member - nfsq[NFS_VERSION_4].u.nfsv4.server.member)/elapsed)
#define nfs4c(member) pdouble(#member, (double)(nfsp[NFS_VERSION_4].u.nfsv4.client.member - nfsq[NFS_VERSION_4].u.nfsv4.client.member)/elapsed)

#define nfs2s_count(member) nfsp[NFS_VERSION_2].u.nfsv2.server.member
#define nfs2c_count(member) nfsp[NFS_VERSION_2].u.nfsv2.client.member

#define nfs3s_count(member) nfsp[NFS_VERSION_3].u.nfsv3.server.member
#define nfs3c_count(member) nfsp[NFS_VERSION_3].u.nfsv3.client.member

#define nfs4s_count(member) nfsp[NFS_VERSION_4].u.nfsv4.server.member
#define nfs4c_count(member) nfsp[NFS_VERSION_4].u.nfsv4.client.member

    psection("NFS_totals");
    nfs(client, calls);
    nfs(client, badcalls);
    nfs(client, clgets);
    nfs(client, cltoomany);
    nfs(server, calls);
    nfs(server, badcalls);
    nfs(server, public_v2);
    nfs(server, public_v3);
    psectionend();

    if (nfs_2_server) {
        if (nfs2s_count(calls)) {
            psection("NFSv2server");
            DEBUG plong("count", nfs2s_count(calls));
            nfs2s(calls);
            nfs2s(null);
            nfs2s(getattr);
            nfs2s(setattr);
            nfs2s(root);
            nfs2s(lookup);
            nfs2s(readlink);
            nfs2s(read);
            nfs2s(writecache);
            nfs2s(write);
            nfs2s(create);
            nfs2s(remove);
            nfs2s(rename);
            nfs2s(link);
            nfs2s(symlink);
            nfs2s(mkdir);
            nfs2s(rmdir),
                nfs2s(readdir);
            nfs2s(statfs);
            psectionend();
        }
    }

    if (nfs_2_client) {
        if (nfs2c_count(calls)) {
            psection("NFSv2client");
            DEBUG plong("count", nfs2c_count(calls));
            nfs2c(calls);
            nfs2c(null);
            nfs2c(getattr);
            nfs2c(setattr);
            nfs2c(root);
            nfs2c(lookup);
            nfs2c(readlink);
            nfs2c(read);
            nfs2c(writecache);
            nfs2c(write);
            nfs2c(create);
            nfs2c(remove);
            nfs2c(rename);
            nfs2c(link);
            nfs2c(symlink);
            nfs2c(mkdir);
            nfs2c(rmdir);
            nfs2c(readdir);
            nfs2c(statfs);
            psectionend();
        }
    }

    if (nfs_3_server) {
        if (nfs3s_count(calls)) {
            psection("NFSv3server");
            DEBUG plong("count", nfs3s_count(calls));
            nfs3s(calls);
            nfs3s(null);
            nfs3s(getattr);
            nfs3s(setattr);
            nfs3s(lookup);
            nfs3s(access);
            nfs3s(readlink);
            nfs3s(read);
            nfs3s(write);
            nfs3s(create);
            nfs3s(mkdir);
            nfs3s(symlink);
            nfs3s(mknod);
            nfs3s(remove);
            nfs3s(rmdir);
            nfs3s(rename);
            nfs3s(link);
            nfs3s(readdir);
            nfs3s(readdirplus);
            nfs3s(fsstat);
            nfs3s(fsinfo);
            nfs3s(pathconf);
            nfs3s(commit);
            psectionend();
        }
    }

    if (nfs_3_client) {
        if (nfs3c_count(calls)) {
            psection("NFSv3client");
            DEBUG plong("count", nfs3c_count(calls));
            nfs3c(calls);
            nfs3c(null);
            nfs3c(getattr);
            nfs3c(setattr);
            nfs3c(lookup);
            nfs3c(access);
            nfs3c(readlink);
            nfs3c(read);
            nfs3c(write);
            nfs3c(create);
            nfs3c(mkdir);
            nfs3c(symlink);
            nfs3c(mknod);
            nfs3c(remove);
            nfs3c(rmdir);
            nfs3c(rename);
            nfs3c(link);
            nfs3c(readdir);
            nfs3c(readdirplus);
            nfs3c(fsstat);
            nfs3c(fsinfo);
            nfs3c(pathconf);
            nfs3c(commit);
            psectionend();
        }
    }

    if (nfs_4_server) {
        if (nfs4s_count(operations)) {
            psection("NFSv4server");
            DEBUG plong("count", nfs4s_count(operations));
            nfs4s(null);
            nfs4s(compound);
            nfs4s(operations);
            nfs4s(access);
            nfs4s(close);
            nfs4s(commit);
            nfs4s(create);
            nfs4s(delegpurge);
            nfs4s(delegreturn);
            nfs4s(getattr);
            nfs4s(getfh);
            nfs4s(link);
            nfs4s(lock);
            nfs4s(lockt);
            nfs4s(locku);
            nfs4s(lookup);
            nfs4s(lookupp);
            nfs4s(nverify);
            nfs4s(open);
            nfs4s(openattr);
            nfs4s(open_confirm);
            nfs4s(open_downgrade);
            nfs4s(putfh);
            nfs4s(putpubfh);
            nfs4s(putrootfh);
            nfs4s(read);
            nfs4s(readdir);
            nfs4s(readlink);
            nfs4s(remove);
            nfs4s(rename);
            nfs4s(renew);
            nfs4s(restorefh);
            nfs4s(savefh);
            nfs4s(secinfo);
            nfs4s(setattr);
            nfs4s(set_clientid);
            nfs4s(clientid_confirm);
            nfs4s(verify);
            nfs4s(write);
            nfs4s(release_lock);
            psectionend();
        }
    }

    if (nfs_4_client) {
        if (nfs4c_count(operations)) {
            psection("NFSv4client");
            DEBUG plong("count", nfs4c_count(operations));
            nfs4c(operations);
            nfs4c(null);
            nfs4c(getattr);
            nfs4c(setattr);
            nfs4c(lookup),
                nfs4c(access),
                nfs4c(readlink);
            nfs4c(read);
            nfs4c(write);
            nfs4c(create);
            nfs4c(mkdir);
            nfs4c(symlink);
            nfs4c(mknod);
            nfs4c(remove);
            nfs4c(rmdir);
            nfs4c(rename);
            nfs4c(link);
            nfs4c(readdir);
            nfs4c(statfs);
            nfs4c(finfo);
            nfs4c(commit);
            nfs4c(open);
            nfs4c(open_confirm),
                nfs4c(open_downgrade);
            nfs4c(close);
            nfs4c(lock);
            nfs4c(unlock);
            nfs4c(lock_test);
            nfs4c(set_clientid);
            nfs4c(renew);
            nfs4c(client_confirm);
            nfs4c(secinfo);
            nfs4c(release_lock);
            nfs4c(replicate);
            nfs4c(pcl_stat);
            nfs4c(acl_stat_l);
            nfs4c(pcl_stat_l),
                nfs4c(acl_read);
            nfs4c(pcl_read);
            nfs4c(acl_write);
            nfs4c(pcl_write);
            nfs4c(delegreturn);
            psectionend();
        }
    }
}
/* - - - - - NFS - - - - */

/* - - - - - gpfs - - - - */
#ifndef NOGPFS
int    gpfs_na = 0; /* Not available, switches off any futher GPFS stats collection attempts */
char    ip[1024]; /* IP address */
char    nn[1024]; /* Node name (I think) */

/* this is the io_s stats data structure */
/* _io_s_ _n_ 192.168.50.20 _nn_ ems1-hs _rc_ 0 _t_ 1548346611 _tu_ 65624 _br_ 0 _bw_ 0 _oc_ 1 _cc_ 1 _rdc_ 0 _wc_ 0 _dir_ 1 _iu_ 0 */
struct gpfs_io {
    long long    rc;
    long long	 t;
    long long    tu;
    long long    br;
    long long    bw;
    long long    oc;
    long long    cc;
    long long    rdc;
    long long    wc;
    long long    dir;
    long long    iu;
} gpfs_io_prev, gpfs_io_curr;

/* this is the fs_io_s stats data structure */
/*_fs_io_s_ _n_ 192.168.50.20 _nn_ ems1-hs _rc_ 0 _t_ 1548519197 _tu_ 560916 _cl_ SBANK_ESS.gpfs.net _fs_ cesroot _d_ 4 _br_ 224331 _bw_ 225922 _o
c_ 63 _cc_ 58 _rdc_ 35 _wc_ 34 _dir_ 2 _iu_ 14 */

#define MAX_FS 64

struct gpfs_fs { /* this is the fs_io_s stats data structure */
    long long    rc;
    long long    t;
    long long    tu;
    char    cl[512];
    char    fs[512];
    long long    d;
    long long    br;
    long long    bw;
    long long    oc;
    long long    cc;
    long long    rdc;
    long long    wc;
    long long    dir;
    long long    iu;
} gpfs_fs_prev[MAX_FS], gpfs_fs_curr[MAX_FS];

int    outfd[2];
int    infd[2];
int    gpfs_pid = -999;


int gpfs_grab()
{
    int i = 0;
    int index = 0;
    int records = 0;
    int ret;
    int count;
    int loops = 0;
    char b[1024];
    char buffer[512 * MAX_FS]; /* 16 very large numbers max 20 digits = 320  so add a bit */

    FUNCTION_START;
    if (gpfs_na)
        return -1;

    if (gpfs_pid != -999) {             /* check we still have mmpmon running in the background */
            ret = kill(gpfs_pid, 0);    /* signal 0 means don't actually send a signal */
            DEBUG fprintf(stderr, "gpfs process kill(%ld, 0) returned =%d [0 is good]\n", gpfs_pid, ret);
            FLUSH;
            if (ret != 0) {
                gpfs_na = 1;
                return -1;
            }
    }

    /* first the total I/O stats */
    count = write(outfd[1], "io_s\n", strlen("io_s\n"));
    if (count != strlen("io_s\n")) {
        DEBUG fprintf(stderr, "gpfs write io_s returned count=%d\n", count);
        FLUSH;
        gpfs_na = 1;
        return 0;
    }
reread:
    loops++;
    DEBUG fprintf(stderr, "gpfs reading io_s\n", count,buffer);
    FLUSH;
    count = read(infd[0], buffer, sizeof(buffer) - 1);
    if( count >= 0)
        buffer[count] = 0; /* end the return buffer */

    if(count > 6 && strncmp(buffer, "_io_s_", 6)) {
        DEBUG fprintf(stderr, "gpfs read io_s but GOT something else & ignoring it. Count=%d text=|%s|\n", count,buffer);
        FLUSH;
        if(loops < 65) /* Sanity check to stop infinite looping */
                goto reread;
    }
    DEBUG fprintf(stderr, "gpfs read io_s and got it Count=%d text=|%s|\n", count,buffer);
    FLUSH;
    if (count > 6) {
        buffer[count] = 0;
        DEBUG fprintf(stderr, "gpfs read io_s count=%d text=|%s|\n", count,buffer);
        FLUSH;
        ret = sscanf(buffer, "_io_s_ _n_ %s _nn_ %s _rc_ %lld _t_ %lld _tu_ %lld _br_ %lld _bw_ %lld _oc_ %lld _cc_ %lld _rdc_ %lld _wc_ %lld _dir_ %lld _iu_ %lld",
                   &ip[0],              /* 1 */
                   &nn[0],              /* 2 */
                   &gpfs_io_curr.rc,    /* 3 */
                   &gpfs_io_curr.t,     /* 4 */
                   &gpfs_io_curr.tu,    /* 5 */
                   &gpfs_io_curr.br,    /* 6 */
                   &gpfs_io_curr.bw,    /* 7 */
                   &gpfs_io_curr.oc,    /* 8 */
                   &gpfs_io_curr.cc,    /* 9 */
                   &gpfs_io_curr.rdc,   /* 10 */
                   &gpfs_io_curr.wc,    /* 11 */
                   &gpfs_io_curr.dir,   /* 12 */
                   &gpfs_io_curr.iu);   /* 13 */
        if(ret != 13){
                DEBUG fprintf(stderr, "GPFS read io_s failed. Returned %d should have been 13\nGPFS=|%s|",ret,buffer);
                FLUSH;
                gpfs_na = 1;
                return 0;
        }
    } else {
        DEBUG fprintf(stderr, "gpfs read io_s bad count=%d\n",count);
        FLUSH;
        gpfs_na = 1;
        return 0;
    }

    /* second the 1 or more filesystem I/O stats */
    count = write(outfd[1], "fs_io_s\n", strlen("fs_io_s\n"));
    if (count > 7 && count != strlen("fs_io_s\n")) {
        DEBUG fprintf(stderr, "gpfs write fs_io_s returned=%d\n", count);
        FLUSH;
        gpfs_na = 1;
        return 0;
    }

    usleep(1000); /* mmpmon does NOT output the many lines of output in one go */
                 /* So pause then we can get them all in one read */
                 /* This works fine on my 5 filesystems test bed system with usleep(100); */
                 /* 1000 = 1/1000th of a second might work if there are lots of GPFS filesystems */

    count = read(infd[0], buffer, sizeof(buffer) - 1);

    if (count > 0) {
        buffer[count] = 0;              /*ensure a zero string ending */
        DEBUG fprintf(stderr, "gpfs read fs_io_s retrieved count=%d text=|%s|\n", count,buffer);
        FLUSH;
        for (i = 0; i < count; i++) {
            if (buffer[i] == '\n')
                records++;
        }
        if (records > MAX_FS)
            records = MAX_FS;
        index = 0;
        for (i = 0; i < records; i++) {
                /*_fs_io_s_ _n_ 192.168.50.20 _nn_ ems1-hs _rc_ 0 _t_ 1548519197 _tu_ 560916 _cl_ SBANK_ESS.gpfs.net _fs_ cesroot _d_ 4 _br_ 224331 _bw_ 225922 _oc_ 63 _cc_ 58 _rdc_ 35 _wc_ 34 _dir_ 2 _iu_ 14 */

                ret = sscanf(&buffer[index],"_fs_io_s_ _n_ %s _nn_ %s _rc_ %lld _t_ %lld _tu_ %lld _cl_ %s _fs_ %s _d_ %lld _br_ %lld _bw_ %lld _oc_ %lld _cc_ %lld _rdc_ %lld _wc_ %lld _dir_ %lld _iu_ %lld",
                        &ip[0],                 /* 1 */
                        &nn[0],                 /* 2 */
                        &gpfs_fs_curr[i].rc,    /* 3 */
                        &gpfs_fs_curr[i].t,     /* 4 */
                        &gpfs_fs_curr[i].tu,    /* 5 */
                        &gpfs_fs_curr[i].cl[0], /* 6 */
                        &gpfs_fs_curr[i].fs[0], /* 7 */
                        &gpfs_fs_curr[i].d,     /* 8 */
                        &gpfs_fs_curr[i].br,    /* 9 */
                        &gpfs_fs_curr[i].bw,    /* 10 */
                        &gpfs_fs_curr[i].oc,    /* 11 */
                        &gpfs_fs_curr[i].cc,    /* 13 */
                        &gpfs_fs_curr[i].rdc,   /* 13 */
                        &gpfs_fs_curr[i].wc,    /* 14 */
                        &gpfs_fs_curr[i].dir,   /* 15 */
                        &gpfs_fs_curr[i].iu);   /* 16  */
            if( ret != 16 ) {
                DEBUG fprintf(stderr, "GPFS read fs_io_s failed. Returned %d should have been 16\nGPFS=|%s|",ret,buffer);
                FLUSH;
                gpfs_na = 1;
                records = 0;
                break;
            }
            for (; index < count; index++) {
                if (buffer[index] == '\n') {    /* find newline = terminating the current record */
                    index++;    /* move to after the newline */
                    break;
                }
            }
            if (index == count)
                break;
        }
    } else {
        DEBUG fprintf(stderr, "gpfs read fs_io_s returned=%d\n", count);
        FLUSH;
        gpfs_na = 1;
    }
    DEBUG fprintf(stderr, "gpfs_grab() returning=%d\n", records);
    return records;
}


void gpfs_init()
{
    char *s;
    int filesystems = 0;
    struct stat sb;             /* to check if mmpmon is executable and gpfs is installed */

    /* call shell script to start mmpmon binary */
    char *argv[] = { "/usr/lpp/mmfs/bin/mmksh", "-c", "/usr/lpp/mmfs/bin/mmpmon -s -p", 0 };    /* */
    char *prog1 = "/usr/lpp/mmfs/bin/mmksh";
    char *prog2 = "/usr/lpp/mmfs/bin/mmpmon";

    /* Alternative: direct start of mmpmon */
    /* char *argv[]={ "/usr/lpp/mmfs/bin/tspmon", "1000", "1", "1", "0", "0", "60", "0", "/var/mmfs/mmpmon/mmpmonSocket", 0}; */

    FUNCTION_START;

    s = getenv("NOGPFS");
    if(s != 0) {
            if(atoi(s) != 0) {
                DEBUG fprintf(stderr, "GPFS off due to shell NOGPFS\n");
                gpfs_na = 1;
                return;
            }
    }

    if( getuid() != 0) {
        DEBUG fprintf(stderr, "GPFS off - not the root user \n");
        gpfs_na = 1;            /* not available = mmpmon required root user */
    }

    if (stat(prog1, &sb) != 0){
        DEBUG fprintf(stderr, "GPFS off - not found = %s\n", prog1);
        gpfs_na = 1;            /* not available = no file */
    }

    if (stat(prog2, &sb) != 0){
        DEBUG fprintf(stderr, "GPFS off - not found = %s\n", prog2);
        gpfs_na = 1;            /* not available = no file */
    }

    if (!(sb.st_mode & S_IXUSR)){
        DEBUG fprintf(stderr, "GPFS off - mmksh not executable\n");
        gpfs_na = 1;            /* not available = not executable */
    }

    if (gpfs_na)
        return;

    if (pipe(outfd) != 0) {     /* Where the parent is going to write outfd[1] to   child input outfd[0] */
        DEBUG fprintf(stderr, "GPFS off - pipe(out) failed\n");
        gpfs_na = 1;
        return;
    }
    if (pipe(infd) != 0) {      /* From where parent is going to read  infd[0] from child output infd[1] */
        DEBUG fprintf(stderr, "GPFS off - pipe(in) failed\n");
        gpfs_na = 1;
        return;
    }
    DEBUG fprintf(stderr, "forking to run GPFS mmpmon command\n");
    if ((gpfs_pid = fork()) == 0) {
        /* child process */
        close(0);
        dup2(outfd[0], 0);

        close(1);
        dup2(infd[1], 1);

        /* Not required for the child */
        close(outfd[0]);
        close(outfd[1]);
        close(infd[0]);
        close(infd[1]);

        execv(argv[0], argv);
        /* never returns */
    } else {
        if(gpfs_pid == -1) {
            DEBUG fprintf(stderr, "GPFS off - fork failed errono =%d\n",errno);
            FLUSH;
            gpfs_na = 1;
            return;
        }
        /* parent process */
        close(outfd[0]);        /* These are being used by the child */
        close(infd[1]);
        usleep(10000);          /* Pause 1/10th to let the child run and stop if GPFS is not running */

        filesystems = gpfs_grab();
        DEBUG fprintf(stderr, "GPFS ready with %d filesystems\n",filesystems);
        FLUSH;

        if( filesystems > 0) {
            /* copy to the previous records for next time */
            memcpy((void *) &gpfs_io_prev, (void *) &gpfs_io_curr,
               sizeof(struct gpfs_io));
            memcpy((void *) &gpfs_fs_prev[0], (void *) &gpfs_fs_curr[0],
               sizeof(struct gpfs_fs) * filesystems);
        }
    }
}

void gpfs_data(double elapsed)
{
    char buffer[10000];
    int records;
    int i;
    int ret;

    FUNCTION_START;
    if (gpfs_na)
        return;

    records = gpfs_grab();

    if(records <= 0)
        return;

#define DELTA_GPFS(xxx)  ((double)(gpfs_io_curr.xxx - gpfs_io_prev.xxx)/elapsed)

    psection("gpfs_io_total");
    pstring("node", ip);
    pstring("name", nn);
    plong("rc", gpfs_io_curr.rc);       /* status */
    plong("time", gpfs_io_curr.t);      /* epoc seconds */
    plong("tu", DELTA_GPFS(tu));
    plong("readbytes", DELTA_GPFS(br));
    plong("writebytes", DELTA_GPFS(bw));
    plong("open", DELTA_GPFS(oc));
    plong("close", DELTA_GPFS(cc));
    plong("reads", DELTA_GPFS(rdc));
    plong("writes", DELTA_GPFS(wc));
    plong("directorylookup", DELTA_GPFS(dir));
    plong("inodeupdate", DELTA_GPFS(iu));
    psectionend();

    memcpy((void *) &gpfs_io_prev, (void *) &gpfs_io_curr,
           sizeof(struct gpfs_io));

#define DELTA_GPFSFS(xxx)  ((double)(gpfs_fs_curr[i].xxx - gpfs_fs_prev[i].xxx)/elapsed)

    psection("gpfs_filesystems");
    for (i = 0; i < records; i++) {
        psub(gpfs_fs_curr[i].fs);
        pstring("node", ip);
        pstring("name", nn);
        plong("rc", gpfs_fs_curr[i].rc);        /* status */
        plong("time", gpfs_fs_curr[i].t);       /* epoc seconds */
        plong("tu", DELTA_GPFSFS(tu));
        pstring("cl", gpfs_fs_curr[i].cl);
        /*pstring("fs",  gpfs_fs_curr[i].fs); */
        plong("disks", gpfs_fs_curr[i].d);
        plong("readbytes", DELTA_GPFSFS(br));
        plong("writebytes", DELTA_GPFSFS(bw));
        plong("open", DELTA_GPFSFS(oc));
        plong("close", DELTA_GPFSFS(cc));
        plong("reads", DELTA_GPFSFS(rdc));
        plong("writes", DELTA_GPFSFS(wc));
        plong("directorylookup", DELTA_GPFSFS(dir));
        plong("inodeupdate", DELTA_GPFSFS(iu));
        psubend();
    }
    psectionend();

    memcpy((void *) &gpfs_fs_prev[0], (void *) &gpfs_fs_curr[0],
           sizeof(struct gpfs_fs) * records);
}
#endif /* NOGPFS */
/* - - - End of GPFS - - - - */

void    ps_part_config_init()
{
    int    rc;
    static perfstat_partition_config_t config;

    FUNCTION_START;
    rc = perfstat_partition_config(NULL, &config, sizeof(perfstat_partition_config_t), 1);
    ASSERT(rc > 0, "perfstat_partition_config()", RETURN, rc);
    if(mode == NIMON)
	save_arch(config.processorFamily);
}

perfstat_partition_config_t config;

void    ps_part_config()
{
    int    i;
    int    unprintable = 0;
    int    rc;

    FUNCTION_START;
    rc = perfstat_partition_config(NULL, &config, sizeof(perfstat_partition_config_t), 1);
    ASSERT(rc > 0, "perfstat_partition_config()", RETURN, rc);

    nominal_mhz = config.processorMHz;
    psection("config");
    pstring("partitionname", config.partitionname);
    pstring("nodename", config.nodename);
    /* phex("partition_type_flags", (long long)(config.conf)); */

    pstring("processorFamily", config.processorFamily);
    pstring("processorModel",  config.processorModel);
    /* Nutanix bug: first 2 chars are ASCII control characters 0x03 & 0x10 */
    unprintable = 0;
    for (i = 0; i < strlen(config.machineID); i++) {
        /* ' ' = 32 = space first regular char */
        if (config.machineID[i] < ' ') {
            unprintable = 1;
            break;
        }
    }
    if (unprintable == 1)
        pstring("machineID", "NutanixBug");
    else
        pstring("machineID", config.machineID);

    pdouble("processorMHz",    config.processorMHz);
    /* plong("pcpu_min",     config.numProcessors.min); this reports zero every time */
    plong("pcpu_max",     config.numProcessors.max);
    /* plong("pcpu_desired", config.numProcessors.desired); this reports zero every time */
    plong("pcpu_online",  config.numProcessors.online);

    pstring("OSname",    config.OSName);
    pstring("OSversion", config.OSVersion);
    pstring("OSbuild",   config.OSBuild);

    plong("lcpus", config.lcpus);
    plong("smtthreads", config.smtthreads);
    plong("drives", config.drives);
    plong("nw_adapter", config.nw_adapters);

    plong("cpucap_min",     config.cpucap.min);
    plong("cpucap_max",     config.cpucap.max);
    plong("cpucap_desired", config.cpucap.desired);
    plong("cpucap_online",  config.cpucap.online);
    plong("cpucap_weightage", config.cpucap_weightage);

    pdouble("entitled_proc_capacity", config.entitled_proc_capacity / 100.0);

    plong("vcpus_min",     config.vcpus.min);
    plong("vcpus_max",     config.vcpus.max);
    plong("vcpus_desired", config.vcpus.desired);
    plong("vcpus_online",  config.vcpus.online);

    plong("processor_poolid", config.processor_poolid);
    plong("activecpusinpool", config.activecpusinpool);
    plong("cpupool_weightage", config.cpupool_weightage);
    plong("sharedpcpu", config.sharedpcpu);
    plong("maxpoolcap", config.maxpoolcap);
    plong("entpoolcap", config.entpoolcap);

    plong("mem_min",     config.mem.min);
    plong("mem_max",     config.mem.max);
    plong("mem_desired", config.mem.desired);
    plong("mem_online",  config.mem.online);
    plong("mem_weightage", config. mem_weightage);

    plong("ams_totiomement", config.totiomement);
    plong("ams_mempoolid",   config.mempoolid);
    plong("ams_hyperpgsize", config.hyperpgsize);
    plong("expanded_mem_min",     config.mem.min);
    plong("expanded_mem_max",     config.mem.max);
    plong("expanded_mem_desired", config.mem.desired);
    plong("expanded_mem_online",  config.mem.online);
    plong("ame_targetmemexpfactor", config.targetmemexpfactor);
    plong("ame_targetmemexpsize",   config.targetmemexpsize);
    phex("subprocessor_mode", config.subprocessor_mode);
    psectionend();
}


/* partition total */
perfstat_partition_total_t partprev;
perfstat_partition_total_t partcurr;
unsigned long long    timebase_saved;
unsigned long long    hardware_ticks;

void    ps_part_total_init()
{
    int    rc;
    char    part_name[IDENTIFIER_LENGTH];

    FUNCTION_START;
    part_name[0] = 0;
    rc = perfstat_partition_total(NULL, &partcurr, sizeof(perfstat_partition_total_t), 1);
    ASSERT(rc > 0, "perfstat_partition_total() init", RETURN, rc);
    timebase_saved = partcurr.timebase_last;
}


void    ps_part_total(double elapsed)
{
    int    rc;
    char    part_name[IDENTIFIER_LENGTH];

    FUNCTION_START;
    /* save the previous values */
    memcpy(&partprev, &partcurr, sizeof(perfstat_partition_total_t));

    part_name[0] = 0;
    rc = perfstat_partition_total(NULL, &partcurr, sizeof(perfstat_partition_total_t), 1);
    ASSERT(rc > 0, "perfstat_partition_total()", RETURN, rc);

    hardware_ticks = partcurr.timebase_last - timebase_saved;
    timebase_saved = partcurr.timebase_last;

    psection("partition_type");
    plong("smt_capable", partcurr.type.b.smt_capable);
    plong("smt_enabled", partcurr.type.b.smt_enabled);
    plong("lpar_capable", partcurr.type.b.lpar_capable);
    plong("lpar_enabled", partcurr.type.b.lpar_enabled);
    plong("shared_capable", partcurr.type.b.shared_capable);
    plong("shared_enabled", partcurr.type.b.shared_enabled);
    plong("dlpar_capable", partcurr.type.b.dlpar_capable);
    plong("capped", partcurr.type.b.capped);
    plong("kernel64bit", partcurr.type.b.kernel_is_64);
    plong("pool_util_authority", partcurr.type.b.pool_util_authority);
    plong("donate_capable", partcurr.type.b.donate_capable);
    plong("donate_enabled", partcurr.type.b.donate_enabled);
    plong("ams_capable", partcurr.type.b.ams_capable);
    plong("ams_enabled", partcurr.type.b.ams_enabled);
    plong("power_save", partcurr.type.b.power_save);
    plong("shared_extended", partcurr.type.b.shared_extended);
    pdouble("invol_virt_cswitch", (partcurr.invol_virt_cswitch - partprev.invol_virt_cswitch) / elapsed);
    pdouble("vol_virt_cswitch", (partcurr.vol_virt_cswitch - partprev.vol_virt_cswitch) / elapsed);
    psectionend();

}


void    ps_processor_pool()
{
    static int    spp_errors = 0;
    static int    spp_in_error = 0;
    int    rc;
    perfstat_rawdata_t rawdata;
    perfstat_processor_pool_util_t pp_util;

    rawdata.type = SHARED_POOL_UTIL;
    rawdata.curstat = &partcurr;
    rawdata.prevstat = &partprev;
    rawdata.sizeof_data = sizeof(perfstat_partition_total_t);
    rawdata.cur_elems = 1;
    rawdata.prev_elems = 1;
    rc = perfstat_processor_pool_util(&rawdata, &pp_util, sizeof(perfstat_processor_pool_util_t), 1);
    if (spp_errors == 0) {
        ASSERT(rc > 0, "perfstat_processor_pool_util() - check HMC: 'Enable Performance Information Collection' = Enabled for this LPAR",
             RETURN, rc);
    }
    if (rc > 0) {
        if (spp_in_error) {
            spp_in_error = 0;
        } else {
            psection("processor_pool");
            plong("pool_id", pp_util.ssp_id);
            plong("max_capacity",      (long)(pp_util.max_capacity / 100));         /* physical units to cores */
            plong("entitled_capacity", (long)(pp_util.entitled_capacity / 100));    /* physical units to cores */
            plong("phys_cpus_pool", pp_util.phys_cpus_pool);
            pdouble("idle_cores", pp_util.idle_cores);
            pdouble("max_cores", pp_util.max_cores );
            pdouble("busy_cores", pp_util.busy_cores );
            pdouble("scaled_busy_cores", pp_util.sbusy_cores );
            pdouble("global_pool_tot_cores", pp_util.gpool_tot_cores );
            pdouble("global_pool_busy_cores", pp_util.gpool_busy_cores );
            psectionend();
        }
    } else {
        spp_errors++;
        spp_in_error = 1;
    }
}


void    ps_one_disk_adapter(perfstat_diskadapter_t dstat, perfstat_diskadapter_t fstat, double elapsed)
{
    char    string[256 + 1];

    FUNCTION_START;
    psub(dstat.name);
    if(strlen(dstat.description) > 0)
        pstring("description", dstat.description);

    if (dstat.adapter_type == SCSI)
        pstring("adapter_type", "SCSI, SAS, other");
    else if (dstat.adapter_type == VHOST)
        pstring("adapter_type", "Virtual SCSI/SAS Adapter");
    else if (dstat.adapter_type == FC)
        pstring("adapter_type", "Fibre Channel");
    else {
        sprintf(string, "unknown=%d", dstat.adapter_type);
        pstring("adapter_type", string);
    }

    plong("devices", dstat.number);
    plong("size_mb", dstat.size);
    plong("free_mb", dstat.free);
    plong("capable_rate_kbps", dstat.xrate);
    plong("bsize", dstat.dk_bsize);

    pdouble("transfers",  ((double)(dstat.xfers     - fstat.xfers)) / elapsed);
    pdouble("rtransfers", ((double)(dstat.dk_rxfers - fstat.dk_rxfers)) / elapsed);
    pdouble("wtransfers", ((double)((dstat.xfers    - dstat.dk_rxfers) - (fstat.xfers - fstat.dk_rxfers) )) / elapsed);
    pdouble("read_kb",    ((double)(dstat.rblks     - fstat.rblks)) / elapsed / 2); /* stat is 512 byt blocks */
    pdouble("write_kb",   ((double)(dstat.wblks     - fstat.wblks)) / elapsed / 2); /* stat is 512 byt blocks */
    pdouble("read_time",  ((double)(dstat.dk_rserv  - fstat.dk_rserv)) / elapsed ); /* read  service time */
    pdouble("write_time", ((double)(dstat.dk_wserv  - fstat.dk_wserv)) / elapsed ); /* write service time */
    pdouble("time", ((double)(dstat.time  - fstat.time )) / elapsed); /* check */
    psubend();
#ifdef RAWSTATS
    sprintf(string, "%s_raw", dstat.name);
    psub(string);
    if(strlen(dstat.description) > 0)
        pstring("description", dstat.description);
    plong("adapter_type", dstat.adapter_type);

    plong("devices", dstat.number);
    plong("size_mb", dstat.size);
    plong("free_mb", dstat.free);
    plong("capable_rate_kbps", dstat.xrate);
    plong("bsize", dstat.dk_bsize);

    plong("transfers",  dstat.xfers);
    plong("rtransfers", dstat.dk_rxfers);
    plong("wtransfers", dstat.xfers);
    plong("read_kb",    dstat.rblks);
    plong("write_kb",   dstat.wblks);
    plong("read_time",  dstat.dk_rserv);
    plong("write_time", dstat.dk_wserv);
    plong("time",       dstat.time);
    psubend();
#endif /* RAWSTATS */
}


/* adpaters */
int    adapters;
perfstat_diskadapter_t *diskadapt;
perfstat_diskadapter_t *disksaved;

void    ps_disk_adapter_init()
{
    int    rc;
    char    adaptname[IDENTIFIER_LENGTH];

    FUNCTION_START;
    /* find out the number of adapters */
    adaptname[0] = 0;
    adapters = perfstat_diskadapter(NULL, NULL, sizeof(perfstat_diskadapter_t), 0);
    ASSERT(adapters > 0, "perfstat_diskadapter(init)", RETURN, adapters);
    if (adapters < 0) {
        adapters = 0;
        return;
    }

    /* printf("%d adapter(s) found\n",adapters); */
    /* just assume these work OK, so no error checking */
    diskadapt = malloc(sizeof(perfstat_diskadapter_t) * adapters);
    ASSERT_PTR(diskadapt != NULL, "malloc", EXIT, diskadapt);

    disksaved  = malloc(sizeof(perfstat_diskadapter_t) * adapters);
    ASSERT_PTR(disksaved != NULL, "malloc", EXIT, disksaved);
    adaptname[0] = 0;
    rc = perfstat_diskadapter((perfstat_id_t * )adaptname, disksaved, sizeof(perfstat_diskadapter_t), adapters);
    ASSERT(rc > 0, "perfstat_diskadapter()", RETURN, rc);
    if (adapters < 0) {
        adapters = 0;
        return;
    }
}


void    ps_disk_adapter_stats(double elapsed)
{
    int    i;
    int    rc;
    char    adaptname[IDENTIFIER_LENGTH];

    FUNCTION_START;
    if (adapters == 0)
        return;
    adaptname[0] = 0;
    rc = perfstat_diskadapter((perfstat_id_t * )adaptname, diskadapt, sizeof(perfstat_diskadapter_t), adapters);
    ASSERT(rc > 0, "perfstat_diskadapter()", RETURN, rc);
    if (adapters < 0) {
        adapters = 0;
        return;
    }


    psection("disk_adapters");
    for (i = 0; i < rc; i++) {
        ps_one_disk_adapter(diskadapt[i], disksaved[i], elapsed);
    }
    psectionend();
    memcpy(disksaved, diskadapt, sizeof(perfstat_diskadapter_t) * adapters);
}


#ifdef VIOS
/* VIOS virtual adpaters */
int    vios_vhosts;
perfstat_diskadapter_t *vhostcurr;
perfstat_diskadapter_t *vhostsave;

void    ps_vios_vhost_init()
{
    int    rc;
    char    vadaptname[IDENTIFIER_LENGTH];

    FUNCTION_START;
    /* find out the number of virtual adapters */
    vadaptname[0] = 0;
    vios_vhosts = perfstat_virtualdiskadapter(NULL, NULL, sizeof(perfstat_diskadapter_t), 0);
    DEBUG printf("perfstat_virtualdiskadapter: %d virtual adapter(s) found\n", vios_vhosts);
    ASSERT(vios_vhosts >= 0, "perfstat_virtualdiskadapter(init)", RETURN, vios_vhosts);
    if (vios_vhosts <= 0) {
        vios_vhosts = 0;
        return;
    }

    /* just assume these work OK, so no error checking */
    vhostcurr = malloc(sizeof(perfstat_diskadapter_t) * vios_vhosts);
    ASSERT_PTR(vhostcurr != NULL, "malloc", EXIT, vhostcurr);

    vhostsave = malloc(sizeof(perfstat_diskadapter_t) * vios_vhosts);
    ASSERT_PTR(vhostsave  != NULL, "malloc", EXIT, vhostsave);
    vadaptname[0] = 0;
    rc = perfstat_virtualdiskadapter((perfstat_id_t * )vadaptname, vhostsave, sizeof(perfstat_diskadapter_t), vios_vhosts);
    ASSERT(rc >= 0, "perfstat_virtualdiskadapter()", RETURN, rc);
    if (vios_vhosts <= 0) {
        vios_vhosts = 0;
        return;
    }
}


void    ps_vios_vhost_stats(double elapsed)
{
    int    i;
    int    rc;
    char    vadaptname[IDENTIFIER_LENGTH];

    FUNCTION_START;
    if (vios_vhosts == 0)
        return;
    vadaptname[0] = 0;
    rc = perfstat_virtualdiskadapter((perfstat_id_t * )vadaptname, vhostcurr, sizeof(perfstat_diskadapter_t), vios_vhosts);
    ASSERT(rc > 0, "perfstat_virtualdiskadapter()", RETURN, rc);
    if (vios_vhosts <= 0) {
        vios_vhosts = 0;
        return;
    }

    psection("vios_vhost");
    for (i = 0; i < rc; i++) {
        ps_one_disk_adapter(vhostcurr[i], vhostsave[i], elapsed);
    }
    psectionend();
    memcpy(vhostsave, vhostcurr, sizeof(perfstat_diskadapter_t) * vios_vhosts);
}
#endif /* VIOS */

/* Fibre Channel adpaters */

void    ps_one_fc_adapter(perfstat_fcstat_t curr, perfstat_fcstat_t save, double e)
{
    char string[256];

    FUNCTION_START;

    if (curr.adapter_type == 0) {
        psub(curr.name);    /* physical name like fcs5 */
    } else {
        psub(curr.vfc_name);    /* virtual name like vfchost6 */
    }
    switch (curr.state) {
	FC_UP:   
		pstring("state", "UP"); 
		break;
	FC_DOWN: 
		pstring("state", "DOWN"); 
		break;
	default: 
		pstring("state", "unknown"); 
		break;
    }

    pdouble("InputRequests",  ((double)(curr.InputRequests  - save.InputRequests)) / e);
    pdouble("OutputRequests", ((double)(curr.OutputRequests - save.OutputRequests)) / e);
    pdouble("InputBytes",     ((double)(curr.InputBytes     - save.InputBytes)) / e);
    pdouble("OutputBytes",    ((double)(curr.OutputBytes    - save.OutputBytes)) / e);

    plong("EffMaxTransfer",   curr.EffMaxTransfer);

    plong("NoDMAResourceCnt", curr.NoDMAResourceCnt);
    plong("NoCmdResourceCnt", curr.NoCmdResourceCnt);

    if (curr.AttentionType == 0)
        pstring("AttentionType",    "Link down");
    else
        pstring("AttentionType",    "Link up");

    plong("SecondsSinceLastReset", curr.SecondsSinceLastReset);

    pdouble("TxFrames",    ((double)(curr.TxFrames - save.TxFrames)) / e);
    pdouble("TxWords",     ((double)(curr.TxWords  - save.TxWords)) / e);
    pdouble("RxFrames",    ((double)(curr.RxFrames - save.RxFrames)) / e);
    pdouble("RxWords",     ((double)(curr.RxWords  - save.RxWords)) / e);

    /* skipped loads of error rates here */

    plong("PortSpeed",  curr.PortSpeed);
    plong("PortSupportedSpeed", curr.PortSupportedSpeed);
    plong("PortFcId",   curr.PortFcId);
    if( strlen(curr.PortType) > 0)
        pstring("PortType", curr.PortType);
    phex("PortWWN",     curr.PortWWN);
    if (curr.adapter_type == 0)
        pstring("adapter_type",    "Fibre Channel");
    if (curr.adapter_type == 1) {
        pstring("adapter_type",   "Virtual Fibre Channel");
        pstring("physical_name", curr.name);
        if( strlen(curr.client_part_name) > 0) 
            pstring("client_part_name", curr.client_part_name);
    }
    psubend();

#ifdef RAWSTATS
    if (curr.adapter_type == 0) {
	sprintf(string,"%s_raw",curr.name);
        psub(string);    /* physical name like fcs5 */
    } else {
	sprintf(string,"%s_raw",curr.vfc_name); 
        psub(string);    /* virtual name like vfchost6 */
    }
    plong("state", curr.state); 

    plong("InputRequests",  curr.InputRequests);
    plong("OutputRequests", curr.OutputRequests);
    plong("InputBytes",     curr.InputBytes);
    plong("OutputBytes",    curr.OutputBytes);

    plong("EffMaxTransfer",   curr.EffMaxTransfer);

    plong("NoDMAResourceCnt", curr.NoDMAResourceCnt);
    plong("NoCmdResourceCnt", curr.NoCmdResourceCnt);

    plong("AttentionType", curr.AttentionType);

    plong("SecondsSinceLastReset", curr.SecondsSinceLastReset);

    pdouble("TxFrames",    curr.TxFrames);
    pdouble("TxWords",     curr.TxWords);
    pdouble("RxFrames",    curr.RxFrames);
    pdouble("RxWords",     curr.RxWords);

    /* skipped loads of error rates here */

    plong("PortSpeed",  curr.PortSpeed);
    plong("PortSupportedSpeed", curr.PortSupportedSpeed);
    plong("PortFcId",   curr.PortFcId);
    if( strlen(curr.PortType) > 0)
        pstring("PortType", curr.PortType);
    phex("PortWWN",     curr.PortWWN);
    plong("adapter_type",  curr.adapter_type);

    if (curr.adapter_type == 1) {
        if( strlen(curr.client_part_name) > 0) 
            pstring("client_part_name", curr.client_part_name);
    }
    psubend();

#endif /* RAWSTATS */
}


int    fc_adapters;
perfstat_fcstat_t *fc_stat;
perfstat_fcstat_t *fc_save;

void    ps_fc_stat_init()
{
    int    rc;
    char    fc_adaptname[IDENTIFIER_LENGTH];

    FUNCTION_START;
    /* find out the number of adapters */
    fc_adaptname[0] = 0;
    fc_adapters = perfstat_fcstat(NULL, NULL, sizeof(perfstat_fcstat_t), 0);
    ASSERT(fc_adapters >= 0, "perfstat_fcstat(init)", EXIT, fc_adapters);
    if (fc_adapters == 0) {
        DEBUG fprintf(stderr, "No Fibre Channel Adapters\n");
        return;
    }

    /* printf("%d fc adapter(s) found\n",fc_adapters); */
    /* just assume these work OK, so no error checking */
    fc_stat = malloc(sizeof(perfstat_fcstat_t) * fc_adapters);
    ASSERT_PTR(fc_stat != NULL, "malloc", EXIT, fc_stat);

    fc_save = malloc(sizeof(perfstat_fcstat_t) * fc_adapters);
    ASSERT_PTR(fc_save  != NULL, "malloc", EXIT, fc_save);
    fc_adaptname[0] = 0;
    rc = perfstat_fcstat((perfstat_id_t * )fc_adaptname, fc_save, sizeof(perfstat_fcstat_t), fc_adapters);
    ASSERT(rc > 0, "perfstat_fcstat(save)", EXIT, rc);
}


void    ps_fc_stats(double elapsed)
{
    int    i;
    int    rc;
    char    fc_adaptname[IDENTIFIER_LENGTH];

    FUNCTION_START;
    if (fc_adapters == 0) 
        return;

    fc_adaptname[0] = 0;
    rc = perfstat_fcstat((perfstat_id_t * )fc_adaptname, fc_stat, sizeof(perfstat_fcstat_t), fc_adapters);
    ASSERT(rc > 0, "perfstat_fcstat()", EXIT, rc);

    psection("fc_adapters");
    for (i = 0; i < rc; i++) {
        ps_one_fc_adapter(fc_stat[i], fc_save[i], elapsed);
    }
    psectionend();
    memcpy(fc_save, fc_stat, sizeof(perfstat_fcstat_t) * fc_adapters);
}


/* VIOS virtual FC adapters */
int    vios_vfc_adapters;
perfstat_fcstat_t *vfc_curr;
perfstat_fcstat_t *vfc_save;

void    ps_vios_vfc_init()
{
    int    rc;
    char    vfc_name[IDENTIFIER_LENGTH];

    FUNCTION_START;
    /* find out the number of virtual FC adapters */
    vfc_name[0] = 0;
    vios_vfc_adapters = perfstat_virtual_fcadapter(NULL, NULL, sizeof(perfstat_fcstat_t), 0);
    DEBUG printf("perfstat_virtual_fcadapter: %d virtual FC adapter(s) found\n", vios_vfc_adapters);
    ASSERT(vios_vfc_adapters >= 0, "perfstat_virtual_fcadapter(init)", RETURN, vios_vfc_adapters);

    if (vios_vfc_adapters <= 0) {
        vios_vfc_adapters = 0;
        return;
    }

    /* just assume these work OK, so no error checking */
    vfc_curr = malloc(sizeof(perfstat_fcstat_t) * vios_vfc_adapters);
    ASSERT_PTR(vfc_curr != NULL, "malloc", EXIT, vfc_curr);

    vfc_save = malloc(sizeof(perfstat_fcstat_t) * vios_vfc_adapters);
    ASSERT_PTR(vfc_curr  != NULL, "malloc", EXIT, vfc_save);
    vfc_name[0] = 0;
    rc = perfstat_virtual_fcadapter((perfstat_id_t * )vfc_name, vfc_save, sizeof(perfstat_fcstat_t), vios_vfc_adapters);
    ASSERT(rc >= 0, "perfstat_virtual_fcadapter(first save)", EXIT, rc);
}


void    ps_vios_vfc_stats(double elapsed)
{
    int    i;
    int    rc;
    char    vfc_name[IDENTIFIER_LENGTH];
    char    tag[256];

    FUNCTION_START;
    if (vios_vfc_adapters == 0)
        return;
    vfc_name[0] = 0;
    rc = perfstat_virtual_fcadapter((perfstat_id_t * )vfc_name, vfc_curr, sizeof(perfstat_fcstat_t), vios_vfc_adapters);
    ASSERT(rc > 0, "perfstat_virtual_fcadapter()", EXIT, rc);

    psection("vios_virtual_fcadapter");
    for (i = 0; i < rc; i++) {
        if( strlen(vfc_curr[i].client_part_name) <= 0) {  
            strcpy(vfc_curr[i].client_part_name, "none");
	}
	if(mode == NIMON) {
            sprintf(tag, ",client_part_name=%s", vfc_curr[i].client_part_name);
            psubtag(tag);
 	}
        ps_one_fc_adapter(vfc_curr[i], vfc_save[i], elapsed);
    }
    psectionend();
    memcpy(vfc_save, vfc_curr, sizeof(perfstat_fcstat_t) * vios_vfc_adapters);
}


/* perfstat_bridgeadapters */
int    net_bridges = 0;
perfstat_netadapter_t *netbridge_statp;
perfstat_netadapter_t *netbridge_statq;

char    first_SEA[256];
char    first_SEA_found = 0;

/* return the network adapter type string */
char    *netadapter_type(netadap_type_t type)
{
    static char    string[64];
    switch (type) {
    case NET_PHY:  return "Physical";
    case NET_SEA:  return "SEA";
    case NET_VIR:  return "Virtual";
    case NET_HEA:  return "HEA";
    case NET_EC:   return "EtherChannel";

#ifndef NET_VLAN /* strangely missing in AIX 7.1 */
#define NET_VLAN 5
#endif /* NET_VLAN */

    case NET_VLAN: return "VLAN";
    default:
        sprintf(string, "unknown=%d", type);
        return string;
    }
}


void    ps_one_net_adapter(perfstat_netadapter_t curr, perfstat_netadapter_t prev, double elapsed)
{
    char    string[256];
    char    tag[256];
#define adapt_delta(xxx)  #xxx, ((double)(curr.xxx - prev.xxx) / elapsed)
#define adapt_num(xxx)    #xxx, ((double)(curr.xxx))

    FUNCTION_START;
    if(mode == NIMON) {
        sprintf(tag, ",network_adapter_type=%s", netadapter_type(curr.adapter_type));
        psubtag(tag);
    }
    psub(curr.name);
    pstring("adapter_type", netadapter_type(curr.adapter_type));
    pdouble(adapt_delta(tx_packets));
    pdouble(adapt_delta(tx_bytes));
    pdouble(adapt_delta(tx_interrupts));
    pdouble(adapt_delta(tx_errors));
    pdouble(adapt_delta(tx_packets_dropped));
    pdouble(adapt_num(tx_queue_size));
    pdouble(adapt_num(tx_queue_len));      /* absolute number */
    pdouble(adapt_num(tx_queue_overflow)); /* absolute number */
    pdouble(adapt_delta(tx_broadcast_packets));
    pdouble(adapt_delta(tx_multicast_packets));
    pdouble(adapt_delta(tx_carrier_sense));
    pdouble(adapt_delta(tx_DMA_underrun));
    pdouble(adapt_delta(tx_lost_CTS_errors));
    pdouble(adapt_delta(tx_max_collision_errors));
    pdouble(adapt_delta(tx_late_collision_errors));
    pdouble(adapt_delta(tx_deferred));
    pdouble(adapt_delta(tx_timeout_errors));
    pdouble(adapt_num(tx_single_collision_count));  /* absolute number */
    pdouble(adapt_num(tx_multiple_collision_count)); /* absolute number */

    pdouble(adapt_delta(rx_packets));
    pdouble(adapt_delta(rx_bytes));
    pdouble(adapt_delta(rx_interrupts));
    pdouble(adapt_delta(rx_errors));
    pdouble(adapt_num(rx_packets_dropped)); /* absolute number */
    pdouble(adapt_num(rx_bad_packets));     /* absolute number */
    pdouble(adapt_delta(rx_multicast_packets));
    pdouble(adapt_delta(rx_broadcast_packets));
    pdouble(adapt_delta(rx_CRC_errors));
    pdouble(adapt_delta(rx_DMA_overrun));
    pdouble(adapt_delta(rx_alignment_errors));
    pdouble(adapt_delta(rx_noresource_errors));
    pdouble(adapt_delta(rx_collision_errors));
    pdouble(adapt_num(rx_packet_tooshort_errors)); /* absolute  number */
    pdouble(adapt_num(rx_packet_toolong_errors));  /* absolute  number */
    pdouble(adapt_delta(rx_packets_discardedbyadapter));
    psubend();
#ifdef RAWSTATS
    sprintf(string,"%s_raw",curr.name);
    psub(string);
    plong("adapter_type", curr.adapter_type);
    plong("tx_packet",curr.tx_packets);
    plong("tx_bytes", curr.tx_bytes);
    plong("tx_interrupts", curr.tx_interrupts);
    plong("tx_errors", curr.tx_errors);
    plong("tx_packets_dropped", curr.tx_packets_dropped);
    plong("tx_queue_size", curr.tx_queue_size);         /* absolute number */
    plong("tx_queue_len", curr.tx_queue_len);           /* absolute number */
    plong("tx_queue_overflow", curr.tx_queue_overflow); /* absolute number */
    plong("tx_broadcast_packets", curr.tx_broadcast_packets);
    plong("tx_multicast_packets", curr.tx_multicast_packets);
    plong("tx_carrier_sense", curr.tx_carrier_sense);
    plong("tx_DMA_underrun", curr.tx_DMA_underrun);
    plong("tx_lost_CTS_errors", curr.tx_lost_CTS_errors);
    plong("tx_max_collision_errors", curr.tx_max_collision_errors);
    plong("tx_late_collision_errors", curr.tx_late_collision_errors);
    plong("tx_deferred", curr.tx_deferred);
    plong("tx_timeout_errors", curr.tx_timeout_errors);
    plong("tx_single_collision_count", curr.tx_single_collision_count);  /* absolute number */
    plong("tx_multiple_collision_count", curr.tx_multiple_collision_count); /* absolute number */

    plong("rx_packets", curr.rx_packets);
    plong("rx_bytes", curr.rx_bytes);
    plong("rx_interrupts", curr.rx_interrupts);
    plong("rx_errors", curr.rx_errors);
    plong("rx_packets_dropped", curr.rx_packets_dropped); /* absolute number */
    plong("rx_bad_packets", curr.rx_bad_packets);     /* absolute number */
    plong("rx_multicast_packets", curr.rx_multicast_packets);
    plong("rx_broadcast_packets", curr.rx_broadcast_packets);
    plong("rx_CRC_errors", curr.rx_CRC_errors);
    plong("rx_DMA_overrun", curr.rx_DMA_overrun);
    plong("rx_alignment_errors", curr.rx_alignment_errors);
    plong("rx_noresource_errors", curr.rx_noresource_errors);
    plong("rx_collision_errors", curr.rx_collision_errors);
    plong("rx_packet_tooshort_errors", curr.rx_packet_tooshort_errors); /* absolute  number */
    plong("rx_packet_toolong_errors", curr.rx_packet_toolong_errors);  /* absolute  number */
    plong("rx_packets_discardedbyadapter", curr.rx_packets_discardedbyadapter);
    psubend();
#endif /* RAWSTATS */
}


void    ps_net_bridge_init()
{
    int    rc;
    perfstat_id_t   netbridge_name;

    FUNCTION_START;
    if (first_SEA_found == 0) /* no SEA = no data */
        return;

    /* check how many perfstat structures are available */
    strcpy(netbridge_name.name, first_SEA);
    net_bridges =  perfstat_bridgedadapters(&netbridge_name, NULL, sizeof(perfstat_netadapter_t), 0);
    ASSERT(net_bridges >= 0, "perfstat_netadapter(init)", EXIT, net_bridges);
    DEBUG fprintf(stderr,"net bridgeadapters=%d\n", net_bridges);
    if (net_bridges == 0) {
        first_SEA_found = 0; /* block further attempts */
        return;
    }
    /* allocate enough memory for all the structures */
    netbridge_statp = malloc(net_bridges * sizeof(perfstat_netadapter_t));
    ASSERT_PTR(netbridge_statp != NULL, "malloc(neta_statp)", EXIT, netbridge_statp);

    netbridge_statq = malloc(net_bridges * sizeof(perfstat_netadapter_t));
    ASSERT_PTR(netbridge_statq != NULL, "malloc(neta_statq)", EXIT, netbridge_statq);

    /* ask to get all the structures available in one call */
    netbridge_name.name[0] = 0;
    strcpy(netbridge_name.name, first_SEA);
    rc = perfstat_bridgedadapters(&netbridge_name, netbridge_statq, sizeof(perfstat_netadapter_t), net_bridges);
    ASSERT(rc > 0, "perfstat_bridgedadapters(1st data)", EXIT, rc);
    ASSERT(rc == net_bridges, "perfstat_bridgedadapters(confused API)", EXIT, net_bridges);
}


void    ps_net_bridge_stats(double elapsed)
{
    int    i;
    int    rc;
    perfstat_id_t   netbridge_name;

    FUNCTION_START;
    if (first_SEA_found == 0) /* no SEA = no data */
        return;
    strcpy(netbridge_name.name, first_SEA);
    rc = perfstat_bridgedadapters(&netbridge_name, netbridge_statp, sizeof(perfstat_netadapter_t), net_bridges);
    ASSERT(rc > 0, "perfstat_bridgedadapters(1st data)", EXIT, rc);

    psection("network_bridged");
    for (i = 0; i < rc; i++) {
        ps_one_net_adapter(netbridge_statp[i], netbridge_statq[i], elapsed);
    }
    psectionend();
    memcpy(netbridge_statq, netbridge_statp, sizeof(perfstat_netadapter_t) * net_bridges);
}


/* perfstat_netadapters */
int    neta_total;
perfstat_netadapter_t *neta_statp;
perfstat_netadapter_t *neta_statq;

void    ps_net_adapter_init()
{
    int    i;
    int    rc;
    perfstat_id_t    neta_name;

    FUNCTION_START;
    /* check how many perfstat structures are available */
    neta_name.name[0] = 0;
    neta_total =  perfstat_netadapter(NULL, NULL, sizeof(perfstat_netadapter_t), 0);
    ASSERT(neta_total > 0, "perfstat_netadapter(init)", EXIT, neta_total);
    DEBUG fprintf(stderr, "netadapters=%d\n", neta_total);

    /* allocate enough memory for all the structures */
    neta_statp = malloc(neta_total * sizeof(perfstat_netadapter_t));
    ASSERT_PTR(neta_statp != NULL, "malloc(neta_statp)", EXIT, neta_statp);
    neta_statq = malloc(neta_total * sizeof(perfstat_netadapter_t));
    ASSERT_PTR(neta_statq != NULL, "malloc(neta_statq)", EXIT, neta_statq);

    /* ask to get all the structures available in one call */
    neta_name.name[0] = 0;
    rc = perfstat_netadapter(&neta_name, neta_statq, sizeof(perfstat_netadapter_t), neta_total);
    ASSERT(rc > 0, "perfstat_netadapter(1st data)", EXIT, rc);

    /* Search for the first SEA - is this might be a VIOS */
    for (i = 0; i < rc; i++) {
        if (neta_statq[i].adapter_type == NET_SEA) {
            strncpy(first_SEA, neta_statq[i].name, 255);
            first_SEA_found = 1;
            DEBUG printf("Saving SEA %s %s.\n", neta_statq[i].name, first_SEA);
            break;
        }
    }
}


void    ps_net_adapter_stats(double elapsed)
{
    int    rc;
    int    i;
    perfstat_id_t neta_name;

    FUNCTION_START;
    neta_name.name[0] = 0;
    rc = perfstat_netadapter(&neta_name, neta_statp, sizeof(perfstat_netadapter_t), neta_total);
    ASSERT(rc > 0, "perfstat_netadapter(data)", EXIT, rc);

#define neta_delta(xxx)  #xxx, ((double)(neta_statp[i].xxx - neta_statq[i].xxx) / elapsed)
#define neta_num(xxx)    #xxx, ((double)(neta_statp[i].xxx))

    psection("network_adapters");
    for (i = 0; i < rc; i++) {
        ps_one_net_adapter(neta_statp[i], neta_statq[i], elapsed);
    }
    psectionend();

    memcpy(neta_statq, neta_statp, sizeof(perfstat_netadapter_t) * neta_total);
}


/* perfstat_netinterface */
int    net_total;
perfstat_netinterface_t *net_statp;
perfstat_netinterface_t *net_statq;

void    ps_net_interface_init()
{
    int    rc;
    char    net_name[IDENTIFIER_LENGTH];

    FUNCTION_START;
    /* check how many perfstat structures are available */
    net_name[0] = 0;
    net_total =  perfstat_netinterface(NULL, NULL, sizeof(perfstat_netinterface_t), 0);
    ASSERT(net_total > 0, "perfstat_netinterface(init)", EXIT, net_total);

    /* allocate enough memory for all the structures */
    net_statp = malloc(net_total * sizeof(perfstat_netinterface_t));
    ASSERT_PTR(net_statp != NULL, "malloc(net_statp)", EXIT, net_statp);

    net_statq = malloc(net_total * sizeof(perfstat_netinterface_t));
    ASSERT_PTR(net_statq != NULL, "malloc(net_statq)", EXIT, net_statq);

    /* ask to get all the structures available in one call */
    net_name[0] = 0;
    rc = perfstat_netinterface((perfstat_id_t * )net_name, net_statq, sizeof(perfstat_netinterface_t), net_total);
    ASSERT(rc > 0, "perfstat_netinterface(data)", EXIT, rc);
}


void    ps_net_interface_stats(double elapsed)
{
    int    rc;
    int    i;
    char    net_name[IDENTIFIER_LENGTH];

    FUNCTION_START;
    net_name[0] = 0;
    rc = perfstat_netinterface((perfstat_id_t * )net_name, net_statp, 
        sizeof(perfstat_netinterface_t), net_total);
    ASSERT(rc > 0, "perfstat_netinterface(data)", EXIT, rc);

#define net_delta(xxx)  #xxx, ((double)(net_statp[i].xxx - net_statq[i].xxx) / elapsed)

    psection("network_interfaces");

    for (i = 0; i < rc; i++) {
        psub(net_statp[i].name);
        if(strlen(net_statp[i].description) > 0)
            pstring("description", net_statp[i].description);
        plong("mtu", net_statp[i].mtu);
        pdouble(net_delta(ipackets));
        pdouble(net_delta(ibytes));
        pdouble(net_delta(ierrors));
        pdouble(net_delta(opackets));
        pdouble(net_delta(obytes));
        pdouble(net_delta(oerrors));
        pdouble(net_delta(collisions));
        pdouble(net_delta(xmitdrops));
        pdouble(net_delta(if_iqdrops));
        pdouble(net_delta(if_arpdrops));
        pdouble("bitrate_mbit", (double)(net_statp[i].bitrate) / 1024.0 / 1024.0);
        psubend();
    }
    psectionend();
    memcpy(net_statq, net_statp, sizeof(perfstat_netinterface_t) * net_total);
}


/* perfstat_netinterface_total */
perfstat_netinterface_total_t nettot_a;
perfstat_netinterface_total_t nettot_b;

void    ps_net_total_init()
{
    int    rc;
    char    net_name[IDENTIFIER_LENGTH];

    FUNCTION_START;
    rc = perfstat_netinterface_total(NULL, &nettot_a, sizeof(perfstat_netinterface_total_t), 1);
    ASSERT(rc > 0, "perfstat_netinterface_total(init)", EXIT, rc);
}


#define nettot_delta(xxx)  #xxx, ((double)(nettot_b.xxx - nettot_a.xxx) / elapsed)

void    ps_net_total_stats(double elapsed)
{
    int    rc;

    FUNCTION_START;
    rc = perfstat_netinterface_total(NULL, &nettot_b, sizeof(perfstat_netinterface_total_t), 1);
    ASSERT(rc > 0, "perfstat_netinterface_total(data)", EXIT, rc);

    psection("network_total");
    plong("networks", nettot_b.number);
    pdouble(nettot_delta(ipackets));
    pdouble(nettot_delta(ibytes));
    pdouble(nettot_delta(ierrors));
    pdouble(nettot_delta(opackets));
    pdouble(nettot_delta(obytes));
    pdouble(nettot_delta(oerrors));
    pdouble(nettot_delta(collisions));
    pdouble(nettot_delta(xmitdrops));
    psectionend();
    memcpy(&nettot_a, &nettot_b, sizeof(perfstat_netinterface_total_t));
}


/* perfstat_cpu */
int    cpu_total; /* used in CPU and Disk stat collection */
perfstat_cpu_t *cpu_statp;
perfstat_cpu_t *cpu_statq;

void    ps_cpu_init()
{
    int    rc;
    char    cpu_name[IDENTIFIER_LENGTH];

    FUNCTION_START;
    /* check how many perfstat structures are available */
    cpu_name[0] = 0;
    cpu_total = perfstat_cpu(NULL, NULL, sizeof(perfstat_cpu_t), 0);
    /* DEBUG printf("rc=%d errno=%d perfstat_cpu(NULL)\n",cpu_total, errno); */
    if (cpu_total <= 0)
        printf("rc=%d errno=%d perfstat_cpu(NULL)\n", cpu_total, errno);
    ASSERT(cpu_total > 0, "perfstat_cpu(init)", EXIT, cpu_total);

    /* allocate enough memory for all the structures */
    cpu_statp = malloc(cpu_total * sizeof(perfstat_cpu_t));
    ASSERT_PTR(cpu_statp != NULL, "malloc(cpu_statp)", EXIT, cpu_statp);

    cpu_statq = malloc(cpu_total * sizeof(perfstat_cpu_t));
    ASSERT_PTR(cpu_statq != NULL, "malloc(cpu_statq)", EXIT, cpu_statq);

    /* ask to get all the structures available in one call */
    cpu_name[0] = 0;
    rc = perfstat_cpu((perfstat_id_t * )cpu_name, cpu_statq, sizeof(perfstat_cpu_t), cpu_total);
    ASSERT(rc > 0, "perfstat_cpu(data)", EXIT, rc);
}


void    ps_cpu_stats(double elapsed,int reduced_stats)
{
    int    rc;
    int    i;
    int    cpu_num;
    long    total;
    char    cpu_name[IDENTIFIER_LENGTH];
    char    cpuname[256];
    int     new_cpu_total;

    FUNCTION_START;
    /* check the number of CPUs is the same */
    cpu_name[0] = 0;
    new_cpu_total = perfstat_cpu(NULL, NULL, sizeof(perfstat_cpu_t), 0);
    if(new_cpu_total != cpu_total) {
	free(cpu_statp);
	free(cpu_statq);
	ps_cpu_init();
	return; /* skip this snapshot or it will be all zeros */
    }
    if(reduced_stats)
	return;

#define CPU_DELTA(name) ((double)(cpu_statp[i].name  - cpu_statq[i].name))

    cpu_name[0] = 0;
    rc = perfstat_cpu((perfstat_id_t * )cpu_name, (perfstat_cpu_t * )cpu_statp, sizeof(perfstat_cpu_t), cpu_total);
    ASSERT(rc > 0, "perfstat_cpu()", EXIT, rc);
    psection("cpu_logicals");
    for (i = 0; i < rc; i++) {
        psub(cpu_statp[i].name);
        /* These are raw number of clock ticks spent so convert into percentages */
        total = (long)(cpu_statp[i].user  - cpu_statq[i].user) + 
            (long)(cpu_statp[i].sys   - cpu_statq[i].sys ) + 
            (long)(cpu_statp[i].wait  - cpu_statq[i].wait) + 
            (long)(cpu_statp[i].idle  - cpu_statq[i].idle);
        if (total <= 0.0) {
            pdouble("user", 0);
            pdouble("sys",  0);
            pdouble("wait", 0);
            pdouble("idle", 0);
        } else {
            pdouble("user", CPU_DELTA(user) * 100.0 / (double)total);
            pdouble("sys",  CPU_DELTA(sys ) * 100.0 / (double)total);
            pdouble("wait", CPU_DELTA(wait) * 100.0 / (double)total);
            pdouble("idle", CPU_DELTA(idle) * 100.0 / (double)total);
        }
        psubend();
    }
    psectionend();

#ifdef RAWSTATS
    psection("cpu_logicals_raw");
    for (i = 0; i < rc; i++) {
        psub(cpu_statp[i].name);
        pdouble("user", cpu_statp[i].user);
        pdouble("sys",  cpu_statp[i].sys );
        pdouble("wait", cpu_statp[i].wait);
        pdouble("idle", cpu_statp[i].idle);
        psubend();
    }
    psectionend();

#endif /* RAWSTATS */

    psection("cpu_physicals");
    for (i = 0; i < rc; i++) {
        /* name looks like this "cpu3" but we want "cpu003" */
        cpu_num = atoi(&cpu_statp[i].name[3]);
        sprintf(cpuname, "cpu%03d", cpu_num);
        psub(cpu_statp[i].name);
        pdouble("user", CPU_DELTA(puser) * 100.0 / (double)hardware_ticks);
        pdouble("sys",  CPU_DELTA(psys ) * 100.0 / (double)hardware_ticks);
        pdouble("wait", CPU_DELTA(pwait) * 100.0 / (double)hardware_ticks);
        pdouble("idle", CPU_DELTA(pidle) * 100.0 / (double)hardware_ticks);
        psubend();
    }
    psectionend();
#ifdef RAWSTATS
    psection("cpu_physicals_raw");
    for (i = 0; i < rc; i++) {
        /* name looks like this "cpu3" but we want "cpu003" */
        cpu_num = atoi(&cpu_statp[i].name[3]);
        sprintf(cpuname, "cpu%03d", cpu_num);
        psub(cpu_statp[i].name);
        pdouble("user", cpu_statp[i].puser);
        pdouble("sys",  cpu_statp[i].psys );
        pdouble("wait", cpu_statp[i].pwait);
        pdouble("idle", cpu_statp[i].pidle);
        psubend();
    }
    psectionend();
#endif /* RAWSTATS */
    psection("cpu_syscalls");
    for (i = 0; i < rc; i++) {
        /* name looks like this "cpu3" but we want "cpu003"  so they list alphabetically */
        cpu_num = atoi(&cpu_statp[i].name[3]);
        sprintf(cpuname, "cpu%03d", cpu_num);
        psub(cpu_statp[i].name);
        pdouble("syscall",    CPU_DELTA(syscall) / elapsed);
        pdouble("sysread",    CPU_DELTA(sysread) / elapsed);
        pdouble("syswrite",   CPU_DELTA(syswrite) / elapsed);
        pdouble("sysfork",    CPU_DELTA(sysfork) / elapsed);
        pdouble("sysexec",    CPU_DELTA(sysexec) / elapsed);
        pdouble("sysreadch",  CPU_DELTA(readch) / elapsed);
        pdouble("syswritech", CPU_DELTA(writech) / elapsed);
        psubend();
    }
    psectionend();
    psection("cpu_dispatch");
    for (i = 0; i < rc; i++) {
        /* name looks like this "cpu3" but we want "cpu003"  so they list alphabetically */
        cpu_num = atoi(&cpu_statp[i].name[3]);
        sprintf(cpuname, "cpu%03d", cpu_num);
        psub(cpu_statp[i].name);
        pdouble("redisp_sd0",      CPU_DELTA(redisp_sd0) / elapsed);
        pdouble("redisp_sd1",      CPU_DELTA(redisp_sd1) / elapsed);
        pdouble("redisp_sd2",      CPU_DELTA(redisp_sd2) / elapsed);
        pdouble("redisp_sd3",      CPU_DELTA(redisp_sd3) / elapsed);
        pdouble("redisp_sd4",      CPU_DELTA(redisp_sd4) / elapsed);
        pdouble("redisp_sd5",      CPU_DELTA(redisp_sd5) / elapsed);
        pdouble("migration_push",  CPU_DELTA(migration_push) / elapsed);
        pdouble("invol_cswitch",   CPU_DELTA(invol_cswitch) / elapsed);
        pdouble("vol_cswitch",     CPU_DELTA(vol_cswitch) / elapsed);

/*
        pdouble("runque",          CPU_DELTA(runque) / elapsed);
#ifdef RAWSTATS
        pdouble("runque_raw",      cpu_statp[i].runque);
#endif 
RAWSTATS */

        psubend();
    }
    psectionend();
    memcpy(cpu_statq, cpu_statp, sizeof(perfstat_cpu_t) * cpu_total);
}


/* PROCESSES */
perfstat_process_t *process_p; /* previous snapsot */
perfstat_process_t *process_c; /* current snapshot */
perfstat_process_t *process_t; /* temporary */
perfstat_process_t *process_u; /* results of the util function */
perfstat_rawdata_t  proc_rawdata;
long    proc_items;
long    proc_last_time;
long    proc_this_time;

double    cpu_threshold = 0.01 ; /* processes using less than this are excluded in the output */

void    ps_process_init()
{
    int    rc;
    perfstat_id_t processname = { "" };

    FUNCTION_START;
    rc = perfstat_process(NULL, NULL, sizeof(perfstat_process_t), 0);
    ASSERT(rc > 0, "perfstat_process(NULL)", EXIT, rc);
    DEBUG printf("%d = perfstat_process(1) - %d\n", rc, errno);

    /* setup the pointers */
    proc_items = rc * 2;  /* add a few incase processes are being created quickly */
    process_p = malloc( (proc_items) * sizeof(perfstat_process_t));
    process_c = malloc( (proc_items) * sizeof(perfstat_process_t));
    process_u = malloc( (proc_items) * sizeof(perfstat_process_t));

    /* get initial set of data  at the current point to be previous at the first stats capture */
    rc = perfstat_process(&processname, process_c, sizeof(perfstat_process_t), proc_items);
    ASSERT(rc > 0, "perfstat_process(data2)", EXIT, rc);
    DEBUG printf("%d = perfstat_process(2) - %d\n", rc, errno);
    proc_this_time = rc;
}


void    ps_process_util(int proc_pid_on)
{
    int    rc;
    int    process_count;
    int    process_saved;
    perfstat_id_t processname = { "" };
    char    procname[128];

    /* Async I/O */
    int    is_aio = 0;
    long    aioprocs = 0;
    long    aiorunning = 0;
    double    aiocpu = 0.0;

    FUNCTION_START;
    /* rotate the data structures */
    process_t = process_p;
    process_p = process_c;
    process_c = process_t;

    proc_last_time = proc_this_time;

    rc = perfstat_process(&processname, process_c, sizeof(perfstat_process_t), proc_items);
    ASSERT(rc > 0, "perfstat_process(data3)", EXIT, rc);
    DEBUG printf("%d = perfstat_process(3) - %d\n", rc, errno);

    proc_this_time = rc;
    /* Set up compare data for utilisation */
    proc_rawdata.type = UTIL_PROCESS;
    proc_rawdata.curstat = process_c;
    proc_rawdata.prevstat = process_p;
    proc_rawdata.sizeof_data = sizeof(perfstat_process_t);
    proc_rawdata.cur_elems = proc_this_time;
    proc_rawdata.prev_elems = proc_last_time;

    rc = perfstat_process_util(&proc_rawdata, process_u, sizeof(perfstat_process_t), proc_items);
    ASSERT(rc > 0, "perfstat_process_util(data)", EXIT, rc);
    DEBUG printf("%d = perfstat_process_util(4) - %d\n", rc, errno);

    if (rc < 1) 
        return;

    /*
    plong("sizeof",  sizeof(perfstat_process_t));
    plong("items",   proc_items);
    plong("returned",rc);
    plong("error",   errno);
    */
    is_aio = 0;
    process_saved = 0;
    for (process_count = 0; process_count < rc; process_count++) {

        /* Async I/O - often used by Oracle */
        /* TESSTING if(!strncmp(process_u[process_count].proc_name, "ncpu", 4)) {*/
        if (!strncmp(process_u[process_count].proc_name, "aioserver", 9)) {
            is_aio = 1;
            aioprocs++;
            aiocpu += process_u[process_count].ucpu_time + process_u[process_count].scpu_time;
        } else {
            is_aio = 0;
        }

        if ( (process_u[process_count].ucpu_time + process_u[process_count].scpu_time) > cpu_threshold) {
            if (is_aio)    /* Async I/O */
                aiorunning++;
 	    if(proc_pid_on) /* "ksh_58295" */
		    sprintf(procname, "%s_%lld", process_u[process_count].proc_name, (long long)process_u[process_count].pid);
	    else	/* "ksh" */
		    sprintf(procname, "%s", process_u[process_count].proc_name);

	    process_saved++;
	    if(process_saved == 1 )
		psection("processes");
            psub(procname);
            plong("pid",             process_u[process_count].pid);
            pstring("name",          process_u[process_count].proc_name);
            plong("priority",        process_u[process_count].proc_priority);
            plong("num_threads",     process_u[process_count].num_threads);
            plong("uid",             process_u[process_count].proc_uid);
            plong("wparid",          process_u[process_count].proc_classid);
            plong("size",            process_u[process_count].proc_size);
            plong("real_mem_data",   process_u[process_count].proc_real_mem_data);
            plong("real_mem_text",   process_u[process_count].proc_real_mem_text);
            plong("virt_mem_data",   process_u[process_count].proc_virt_mem_data);
            plong("virt_mem_text",   process_u[process_count].proc_virt_mem_text);
            plong("shared_lib_data", process_u[process_count].shared_lib_data_size);
            plong("heap_size",       process_u[process_count].heap_size);
            plong("real_inuse",      process_u[process_count].real_inuse);
            plong("virt_inuse",      process_u[process_count].virt_inuse);
            plong("pinned",          process_u[process_count].pinned);
            plong("pgsp_inuse",      process_u[process_count].pgsp_inuse);
            plong("filepages",       process_u[process_count].filepages);
            plong("real_inuse_map",  process_u[process_count].real_inuse_map);
            plong("virt_inuse_map",  process_u[process_count].virt_inuse_map);
            plong("pinned_inuse_map",process_u[process_count].pinned_inuse_map);
            pdouble("ucpu_time",     process_u[process_count].ucpu_time);
            pdouble("scpu_time",     process_u[process_count].scpu_time);
            /* plong("last_timebase",process_u[process_count].last_timebase); */
            plong("inBytes",         process_u[process_count].inBytes);
            plong("outBytes",        process_u[process_count].outBytes);
            plong("inOps",           process_u[process_count].inOps);
            plong("outOps",          process_u[process_count].outOps);
            psubend();
        }
    }
    if(process_saved > 0 )
        psectionend();
    if (aioprocs) {
        psection("aioserver");
        plong("aioprocs", aioprocs);
        plong("aiorunning", aiorunning);
        pdouble("aiocpu", aiocpu);
        psectionend();
    }
}


/* CPU TOTAL */
/* macro to calculate the difference between previous and current values */
#define DELTA(member) (cpu_tot_p->member - cpu_tot_q->member)
#define DELTAD(member) (double)((double)cpu_tot_p->member - (double)cpu_tot_q->member)

/* the two copies of the cpu data */
perfstat_cpu_total_t cpu_tot[2];

perfstat_cpu_total_t *cpu_tot_q; /* current snapshot */
perfstat_cpu_total_t *cpu_tot_p; /* previous snapsot */
perfstat_cpu_total_t *cpu_tot_t; /* temporary */
perfstat_cpu_util_t cpu_util;
perfstat_rawdata_t rawdata;


void    ps_cpu_total_init()
{
    int    rc;

    FUNCTION_START;
    /* setup the pointers */
    cpu_tot_q = &cpu_tot[0];
    cpu_tot_p = &cpu_tot[1];
    /* get initial set of data */
    rc = perfstat_cpu_total(NULL, cpu_tot_q, sizeof(perfstat_cpu_total_t), 1);
    ASSERT(rc > 0, "perfstat_cpu_total(init)", EXIT, rc);

    /* Set up compare data for utilisation */
    rawdata.type = UTIL_CPU_TOTAL;
    rawdata.curstat = cpu_tot_p;
    rawdata.prevstat = cpu_tot_q;
    rawdata.sizeof_data = sizeof(perfstat_cpu_total_t);
    rawdata.cur_elems = 1;
    rawdata.prev_elems = 1;

    rc = perfstat_cpu_util(&rawdata, &cpu_util, sizeof(perfstat_cpu_util_t), 1);
    ASSERT(rc > 0, "perfstat_cpu_util(init)", EXIT, rc);
}

void replaces(char *str, char *orig, char *rep)
{
  char *p;

  if(!(p = strstr(str, orig)))
    return;

  *p = 0;
  strcat(p, rep);
  strcat(p + strlen(rep), p + strlen(orig));
}

void    uptime()
{
    FILE * pop;
    char    string[256], *s;
    int    ret;
    int    i;
 
    int    days = 0;
    int    hours = 0;
    int    mins = 0;
    int    users = 0;
    int    good = 0;
    /*
        $ uptime -u
          06:56PM   up 49 mins,  1 user,  load average: 0.70, 0.75, 0.70
          08:37PM   up   2:30,  3 user,  load average: 1.23, 1.12, 1.01
          06:08PM   up 212 days,   48 min,  9 user,  load average: 3.28, 2.52, 2.29
          06:08PM   up 212 days,   48 mins,  9 user,  load average: 3.28, 2.52, 2.29
          06:08PM   up 212 days,   6:48,  9 user,  load average: 3.28, 2.52, 2.29
          08:07AM   up 14 hrs,  1 user,  load average: 4.17, 3.54, 2.58
        */
    if ( (pop = popen("/usr/bin/uptime -u 2>/dev/null", "r") ) != NULL ) {
        if (fgets(string, 256, pop) != NULL) {
            for (i = 0; i < strlen(string); i++) { /* remove commas & newline */

                if (string [i] == ',')
                    string[i] = ' ';
                if (string[i] == '\n')
                    string[i] = ' ';
            }
            s = &string[14]; /* remove the time, AM|PM and up */

	    /* remove plurals */
	    replaces(s, "days",  "day");
	    replaces(s, "hours", "hour");
	    replaces(s, "hrs",   "hr");
	    replaces(s, "mins",  "min");

            /* days H:M + user */
            days = hours = mins = users = 0;
            if ( sscanf(s, "%d day %d:%d %d user", &days, &hours, &mins, &users) == 4) {
                good = 1;
            } else {
                /* H:M + user */
                days = hours = mins = users = 0;
                if (sscanf(s, "%d:%d %d user", &hours, &mins, &users) == 3) {
                    good = 1;
                } else {
                    /* days + min + user */
                    days = hours = mins = users = 0;
                    if (sscanf(s, "%d day %d min %d user", &days, &mins, &users) == 3) { /* min & mins */
                        good = 1;
                    } else {
                            /* days + hrs + user */
                            days = hours = mins = users = 0;
                            if (sscanf(s, "%d day %d hr %d user", &days, &hours, &users) == 3) {
                                good = 1;
                            } else {
                                /* min + user */
                                days = hours = mins = users = 0;
                                if (sscanf(s, "%d min %d user", &mins, &users) == 2) {
                                    good = 1;
                                } else {
                                    /* hrs + user */
                                    days = hours = mins = users = 0;
                                    if (sscanf(s, "%d hr %d user", &hours, &users) == 2) {
                                        good = 1;
                                    } else {
                                        /* day + user */
                                        days = hours = mins = users = 0;
                                        if (sscanf(s, "%d day %d user", &days, &users) == 2) {
                                            good = 1;
                                        }
                                    }
                                }
                            }
                    }
                }
            }
            if (good) {
                psection("uptime");
                /* printf("scanf ret=%d days=%d hours=%d mins=%d users=%d\n", ret, days, hours, mins, users); */
                plong("days", days);
                plong("hours", hours);
                plong("minutes", mins);
                plong("users", users);
                psectionend();
            } else {
                psection("uptime_output");
                pstring("output", string);
                psectionend();
            }
        }
        pclose(pop);
    }
}


void    ps_cpu_total_stats(double elapsed)
{
    int    rc;
    double    total;
    double    ptotal;

    FUNCTION_START;
    rc = perfstat_cpu_total(NULL, cpu_tot_p, sizeof(perfstat_cpu_total_t), 1);
    ASSERT(rc > 0, "perfstat_cpu_total(NULL)", EXIT, rc);

    /* Set up compare data for utilisation */
    rawdata.type = UTIL_CPU_TOTAL;
    rawdata.curstat = cpu_tot_p;
    rawdata.prevstat = cpu_tot_q;
    rawdata.sizeof_data = sizeof(perfstat_cpu_total_t);
    rawdata.cur_elems = 1;
    rawdata.prev_elems = 1;

    rc = perfstat_cpu_util(&rawdata, &cpu_util, sizeof(perfstat_cpu_util_t), 1);
    ASSERT(rc > 0, "perfstat_cpu_util(data)", EXIT, rc);

    current_mhz = nominal_mhz * cpu_util.freq_pct / 100.0;

    psection("cpu_util");
    pdouble("user_pct",        cpu_util.user_pct);
    pdouble("kern_pct",        cpu_util.kern_pct);
    pdouble("idle_pct",        cpu_util.idle_pct);
    pdouble("wait_pct",        cpu_util.wait_pct);

    pdouble("physical_busy", cpu_util.physical_busy);
    pdouble("physical_consumed", cpu_util.physical_consumed);

    pdouble("idle_donated_pct", cpu_util.idle_donated_pct);
    pdouble("busy_donated_pct", cpu_util.busy_donated_pct);

    pdouble("idle_stolen_pct", cpu_util.idle_stolen_pct);
    pdouble("busy_stolen_pct", cpu_util.busy_stolen_pct);

    pdouble("entitlement",        cpu_util.entitlement);
    pdouble("entitlement_pct",  cpu_util.entitlement_pct);
    pdouble("freq_pct",        cpu_util.freq_pct);
    pdouble("nominal_mhz",        nominal_mhz);
    pdouble("current_mhz",        current_mhz);
    psectionend();

    psection("cpu_details");
    plong("cpus_active",     cpu_tot_p->ncpus);
    plong("cpus_configured", cpu_tot_p->ncpus_cfg);
    pdouble("mhz",         (double) (cpu_tot_p->processorHZ / 1000000));
    pstring("cpus_description", cpu_tot_p->description);
    psectionend();

    psection("kernel");
    pdouble("pswitch",         DELTA(pswitch) / elapsed);
    pdouble("syscall",         DELTA(syscall) / elapsed);
    pdouble("sysread",         DELTA(sysread) / elapsed);
    pdouble("syswrite",        DELTA(syswrite) / elapsed);
    pdouble("sysfork",         DELTA(sysfork) / elapsed);
    pdouble("sysexec",         DELTA(sysexec) / elapsed);

    pdouble("readch",          DELTA(readch) / elapsed);
    pdouble("writech",         DELTA(writech) / elapsed);

    pdouble("devintrs",        DELTA(devintrs) / elapsed);
    pdouble("softintrs",       DELTA(softintrs) / elapsed);

    pdouble("load_avg_1_min",  (double)cpu_tot_p->loadavg[0] / (double)(1 << SBITS));
    pdouble("load_avg_5_min",  (double)cpu_tot_p->loadavg[1] / (double)(1 << SBITS));
    pdouble("load_avg_15_min", (double)cpu_tot_p->loadavg[2] / (double)(1 << SBITS));

    /* removed as long -> float see below
    plong("runque",            DELTA(runque)); 
    plong("swpque",            DELTA(swpque)); 
    */
    if (DELTA(runque) == 0 || DELTA(runocc) == 0)
        pdouble("run_queue", 0.0);
    else
        pdouble("run_queue",   ((double)(DELTA(runque))) / ((double)(DELTA(runocc)))); /* fixed */
    if (DELTA(swpque) == 0 || DELTA(swpocc) == 0)
        pdouble("swp_queue", 0.0);
    else
        pdouble("swp_queue",     ((double)(DELTA(swpque))) / ((double)(DELTA(swpocc)))); /* fixed */

    pdouble("bread",           DELTA(bread) / elapsed);
    pdouble("bwrite",          DELTA(bwrite) / elapsed);
    pdouble("lread",           DELTA(lread) / elapsed);
    pdouble("lwrite",          DELTA(lwrite) / elapsed);
    pdouble("phread",          DELTA(phread) / elapsed);
    pdouble("phwrite",         DELTA(phwrite) / elapsed);

    plong("runocc_count",      DELTA(runocc));
    plong("swpocc_count",      DELTA(swpocc));
    /*
    plong("runocc_avg",        DELTA(runocc) / elapsed);
    plong("swpocc_avg",        DELTA(swpocc) / elapsed);
    */
    pdouble("runocc_average",  DELTA(runocc) / elapsed);
    pdouble("swpocc_average",  DELTA(swpocc) / elapsed);

    pdouble("iget",            DELTA(iget) / elapsed);
    pdouble("namei",           DELTA(namei) / elapsed);
    pdouble("dirblk",          DELTA(dirblk) / elapsed);

    pdouble("msg",             DELTA(msg) / elapsed);
    pdouble("sema",            DELTA(sema) / elapsed);
    pdouble("rcvint",          DELTA(rcvint) / elapsed);
    pdouble("xmtint",          DELTA(xmtint) / elapsed);
    pdouble("mdmint",          DELTA(mdmint) / elapsed);
    pdouble("tty_rawinch",     DELTA(tty_rawinch) / elapsed);
    pdouble("tty_caninch",     DELTA(tty_caninch) / elapsed);
    pdouble("tty_rawoutch",    DELTA(tty_rawoutch) / elapsed);

    pdouble("ksched",          DELTA(ksched) / elapsed);
    pdouble("koverf",          DELTA(koverf) / elapsed);
    pdouble("kexit",           DELTA(kexit) / elapsed);

    pdouble("rbread",          DELTA(rbread) / elapsed);
    pdouble("rcread",          DELTA(rcread) / elapsed);
    pdouble("rbwrt",           DELTA(rbwrt) / elapsed);
    pdouble("rcwrt",           DELTA(rcwrt) / elapsed);

    pdouble("traps",           DELTA(traps) / elapsed);

    plong("ncpus_high",        cpu_tot_p->ncpus_high); /* new */
    pdouble("decrintrs",       DELTA(decrintrs) / elapsed); /* new */
    pdouble("mpcrintrs",       DELTA(mpcrintrs) / elapsed); /* new */
    pdouble("mpcsintrs",       DELTA(mpcsintrs) / elapsed); /* new */
    pdouble("phantintrs",      DELTA(phantintrs) / elapsed); /* new */

    pdouble("idle_donated_purr",    (double)DELTA(idle_donated_purr) );
    pdouble("idle_donated_spurr",   (double)DELTA(idle_donated_spurr) );
    pdouble("busy_donated_purr",    (double)DELTA(busy_donated_purr) );
    pdouble("busy_donated_spurr",   (double)DELTA(busy_donated_spurr) );
    pdouble("idle_stolen_purr",     (double)DELTA(idle_stolen_purr) );
    pdouble("idle_stolen_spurr",    (double)DELTA(idle_stolen_spurr) );
    pdouble("busy_stolen_purr",     (double)DELTA(busy_stolen_purr) );
    pdouble("busy_stolen_spurr",    (double)DELTA(busy_stolen_spurr) );

    plong("iowait",            cpu_tot_p->iowait );
    plong("physio",            cpu_tot_p->physio );
    plong("twait",             cpu_tot_p->twait );

    pdouble("hpi",            (double)DELTA(hpi) / elapsed );
    pdouble("hpit",           (double)DELTA(hpit) / elapsed );
#ifdef RAWSTATS
    plong("hpit_raw",         cpu_tot_p->hpit );
#endif /* RAWSTATS */

    plong("spurrflag",         cpu_tot_p->spurrflag);
    plong("tb_last",           cpu_tot_p->tb_last);
    pdouble("purr_coalescing", (double)DELTA(purr_coalescing) / elapsed );
    pdouble("spurr_coalescing",(double)DELTA(spurr_coalescing) / elapsed );
    psectionend();

    total  = DELTA(user) + DELTA(sys) + DELTA(idle) + DELTA(wait);

    psection("cpu_logical_total");
    pdouble("user", 100.0 * (double) DELTA(user) /  total);
    pdouble("sys",  100.0 * (double) DELTA(sys)  / total);
    pdouble("wait", 100.0 * (double) DELTA(wait) / total);
    pdouble("idle", 100.0 * (double) DELTA(idle) / total);
    psectionend();

    ptotal  = DELTA(puser) + DELTA(psys) + DELTA(pidle) + DELTA(pwait);
    psection("cpu_physical_total");
    pdouble("user", 100.0 * (double) DELTA(puser) / ptotal);
    pdouble("sys",  100.0 * (double) DELTA(psys)  / ptotal);
    pdouble("wait", 100.0 * (double) DELTA(pwait) / ptotal);
    pdouble("idle", 100.0 * (double) DELTA(pidle) / ptotal);
    psectionend();

    ptotal  = DELTA(puser_spurr) + DELTA(psys_spurr) + DELTA(pidle_spurr) + DELTA(pwait_spurr);

    psection("cpu_physical_total_spurr");
    pdouble("puser", 100.0 * (double) DELTA(puser_spurr) / ptotal);
    pdouble("psys",  100.0 * (double) DELTA(psys_spurr)  / ptotal);
    pdouble("pidle", 100.0 * (double) DELTA(pidle_spurr) / ptotal);
    pdouble("pwait", 100.0 * (double) DELTA(pwait_spurr) / ptotal);
    psectionend();

    /* Swap the pointer around ready for next time */
    cpu_tot_t = cpu_tot_p;
    cpu_tot_p = cpu_tot_q;
    cpu_tot_q = cpu_tot_t;
}


char    junk1[1024];
struct vminfo vmi_prev;
char    junk2[1024];
struct vminfo vmi_now;
char    junk3[1024];

void    ps_vminfo_init()
{
    int    rc;

    FUNCTION_START;
    rc = vmgetinfo(&vmi_prev, VMINFO, sizeof(struct vminfo ));
    ASSERT(rc == 0, "vmgetinfo(init)", EXIT, rc);
}


void    ps_vminfo(double elapsed)
{
    int    rc;

#define vminfo_double(xxx)     pdouble( # xxx, ((double)(vmi_now.xxx - vmi_prev.xxx)) / (double)elapsed);
#define vminfo_long(xxx)     plong  ( # xxx, (long long)(vmi_now.xxx));

    FUNCTION_START;
    ASSERT(elapsed != 0.0, "vmgetinfo(data) elapsed", DUMP, (long long)elapsed);
    rc = vmgetinfo(&vmi_now, VMINFO, sizeof(struct vminfo ));
    ASSERT(rc == 0, "vmgetinfo(data)", EXIT, rc);

    psection("vminfo");
    vminfo_double(pgexct);    /* see /usr/include/sys/vminfo.h these are incrementing counters */
    vminfo_double(pgrclm);
    vminfo_double(lockexct);
    vminfo_double(backtrks);
    vminfo_double(pageins);
    vminfo_double(pageouts);
    vminfo_double(pgspgins);
    vminfo_double(pgspgouts);
    vminfo_double(numsios);
    vminfo_double(numiodone);
    vminfo_double(zerofills);
    vminfo_double(exfills);
    vminfo_double(scans);
    vminfo_double(cycles);
    vminfo_double(pgsteals);
    /* other vallues available but what do they mean  to non AIX Kernal programmers */

    vminfo_long(numfrb);        /* see /usr/include/sys/vminfo.h these are values */
    vminfo_long(numclient);
    vminfo_long(numcompress);
    vminfo_long(numperm);
    vminfo_long(maxperm);
    vminfo_long(memsizepgs);
    vminfo_long(numvpages);
    vminfo_long(minperm);
    vminfo_long(minfree);
    vminfo_long(maxfree);
    vminfo_long(maxclient);
    vminfo_long(npswarn);
    vminfo_long(npskill);
    vminfo_long(minpgahead);
    vminfo_long(maxpgahead);
    vminfo_long(ame_memsizepgs);
    vminfo_long(ame_numfrb);
    vminfo_long(ame_factor_tgt);
    vminfo_long(ame_factor_actual);
    vminfo_long(ame_deficit_size);

    /* another 100 stats in here but only a kernel programmer would understand them */
    psectionend();
    memcpy(&vmi_prev, &vmi_now, sizeof(struct vminfo ) );
}


perfstat_tape_t *tape_prev;
perfstat_tape_t *tape_now;
int    tapes;

void    ps_tape_init()
{
    int    rc;
    perfstat_id_t first;

    FUNCTION_START;
    DEBUG fprintf(stderr, "ps_tape_init()\n");
    tapes = perfstat_tape(NULL, NULL, sizeof(perfstat_tape_t), 0);
    DEBUG fprintf(stderr, "ps_tape_init number of tapes=%d\n", tapes);

    /* return code is number of structures returned */
    ASSERT(tapes >= 0, "perfstat_tape(init)", EXIT, tapes);
    if (tapes == 0 ) {
        return;
    }
    tape_prev = malloc(sizeof(perfstat_tape_t) * tapes);
    ASSERT_PTR(tape_prev != NULL, "malloc(tape_prev)", EXIT, tape_prev);
    tape_now  = malloc(sizeof(perfstat_tape_t) * tapes);
    ASSERT_PTR(tape_now != NULL, "malloc(tape_now)", EXIT, tape_now);
    strcpy(first.name, FIRST_TAPE);
    rc = perfstat_tape(&first, tape_prev, sizeof(perfstat_tape_t), tapes);
}


void    ps_tape(double elapsed)
{
    int    rc;
    int    i;
    perfstat_id_t first;

#define tape_long(xxx)         plong(   # xxx, tape_now[i].xxx);
#define tape_double(xxx)    pdouble( # xxx, ((double)(tape_now[i].xxx - tape_prev[i].xxx)) / (double)elapsed);

    FUNCTION_START;
    if (tapes == 0) {    /* dont output anything if no tape drives found */
        return;
    }
    DEBUG fprintf(stderr, "ps_tape() tapes=%d\n", tapes);
    strcpy(first.name, FIRST_TAPE);
    rc = perfstat_tape(&first, tape_now, sizeof(perfstat_tape_t), tapes);
    /* return code is number of structures returned */
    ASSERT(rc > 0, "perfstat_tapes(data)", EXIT, tapes);
    psection("tapes");
    for (i = 0; i < rc; i++) {
        psub(tape_now[i].name);
	if (strlen(tape_now[i].description) > 0)
            pstring("description", tape_now[i].description);

        tape_long( size);
        tape_long( free);
        tape_long( bsize);

        pstring("adapter", tape_now[i].adapter);
        tape_long(paths_count);

        tape_double(xfers);
        tape_double(rxfers);
        tape_double(wblks);
        tape_double(rblks);
        tape_double(time);

        tape_double(rserv);
        tape_double(rtimeout);
        tape_double(rfailed);
        tape_long(min_rserv);
        tape_long(max_rserv);
        tape_double(wserv);
        tape_double(wtimeout);
        tape_double(wfailed);
        tape_long(min_wserv);
        tape_long(max_wserv);

        psubend();
    }
    psectionend();
    memcpy(tape_prev, tape_now, sizeof(perfstat_tape_t) * tapes );
}


perfstat_memory_page_t mem_page_prev[4];
perfstat_memory_page_t mem_page_now[4];
int    mem_pages;

void    ps_memory_page_init()
{
    int    rc;
    perfstat_psize_t pagesize;

    FUNCTION_START;
    mem_pages = perfstat_memory_page(NULL, NULL, sizeof(perfstat_memory_page_t), 0);

    /* return code is number of structures returned */
    ASSERT(mem_pages > 0, "perfstat_memory_page(init)", RETURN, mem_pages);
    if (mem_pages <= 0) {    /* found compiled for 7.1 TL4 sp2 fails on AIX 7.1 TL4 sp4 */
        mem_pages = 0;
    }
    pagesize.psize = FIRST_PSIZE;
    rc = perfstat_memory_page(&pagesize, &mem_page_prev[0], sizeof(perfstat_memory_page_t), mem_pages);
}


void    ps_memory_page(double elapsed)
{
    int    rc;
    int    i;
    perfstat_psize_t pagesize;

#define mp_long(xxx)         plong(   # xxx, mem_page_now[i].xxx);
#define mp_double(xxx)        pdouble( # xxx, ((double)(mem_page_now[i].xxx - mem_page_prev[i].xxx)) / (double)elapsed);

    FUNCTION_START;
    if (mem_pages == 0) {     /* found compiled for 7.1 TL4 sp2 fails on AIX 7.1 TL4 sp4 */
        return;
    }
    pagesize.psize = FIRST_PSIZE;
    rc = perfstat_memory_page(&pagesize, &mem_page_now[0], sizeof(perfstat_memory_page_t), mem_pages);
    /* return code is number of structures returned */
    ASSERT(rc > 0, "perfstat_memory_page(data)", EXIT, rc);
    psection("memory_page");
    for (i = 0; i < rc; i++) {
        switch (mem_page_now[i].psize) {
        case PAGE_4K:  
            psub("4KB"); 
            break;
        case PAGE_64K: 
            psub("64KB"); 
            break;
        case PAGE_16M: 
            psub("16MB"); 
            break;
        case PAGE_16G: 
            psub("16GB"); 
            break;
        default: 
            psub("unknown"); 
            break;
        }
        mp_long( real_total);
        mp_long( real_free);
        mp_long( real_pinned);
        mp_long( real_inuse);
        mp_double( pgexct);
        mp_double( pgins);
        mp_double( pgouts);
        mp_double( pgspins);
        mp_double( pgspouts);
        mp_double( scans);
        mp_double( cycles);
        mp_double( pgsteals);
        mp_long( numperm);
        mp_long( numpgsp);
        mp_long( real_system);
        mp_long( real_user);
        mp_long( real_process);
        mp_long( virt_active);
        mp_long( comprsd_total);
        mp_long( comprsd_wseg_pgs);
        mp_double( cpgins);
        mp_double( cpgouts);

        mp_long( cpool_inuse);
        mp_long( ucpool_size);
        mp_long( comprsd_wseg_size);
        mp_long( real_avail);
        psubend();
    }
    psectionend();
    memcpy(&mem_page_prev, &mem_page_now, sizeof(perfstat_memory_page_t) * mem_pages );
}


perfstat_memory_total_t mem_prev;
perfstat_memory_total_t mem_now;

void    ps_memory_init()
{
    int    rcy;
    int    rc;

    FUNCTION_START;
    rc = perfstat_memory_total(NULL, &mem_prev, sizeof(perfstat_memory_total_t), 1);
    /* return code is number of structures returned */
    ASSERT(rc > 0, "perfstat_memory_total(init)", EXIT, rc);
}


void    ps_memory(double elapsed)
{
    int    rc;

#define memory_long(xxx)   plong(   # xxx, mem_now.xxx);
#define memory_double(xxx) pdouble( # xxx, ((double)(mem_now.xxx - mem_prev.xxx)) / (double)elapsed);

    FUNCTION_START;
    rc = perfstat_memory_total(NULL, &mem_now, sizeof(perfstat_memory_total_t), 1);
    /* return code is number of structures returned */
    ASSERT(rc > 0, "perfstat_memory_total(data)", EXIT, rc);

    psection("memory");
    memory_long(virt_total);
    memory_long(real_total);
    memory_long(real_free);
    memory_long(real_pinned);
    memory_long(real_inuse);
    memory_double(pgbad);
    memory_double(pgexct);
    memory_double(pgins);
    memory_double(pgouts);
    memory_double(pgspins);
    memory_double(pgspouts);
    memory_double(scans);
    memory_double(cycles);
    memory_double(pgsteals);
    memory_long(numperm);
    memory_long(pgsp_total);
    memory_long(pgsp_free);
    memory_long(pgsp_rsvd);

    memory_long(real_system);
    memory_long(real_user);
    memory_long(real_process);
    memory_long(virt_active);

    memory_long(iome);
    memory_long(iomu);
    memory_long(iohwm);
    memory_long(pmem);

    memory_long(comprsd_total);
    memory_long(comprsd_wseg_pgs);
    memory_long(cpgins);
    memory_long(cpgouts);
    memory_long(true_size);
    memory_long(expanded_memory);
    memory_long(comprsd_wseg_size);
    memory_long(target_cpool_size);
    memory_long(max_cpool_size);
    memory_long(min_ucpool_size);
    memory_long(cpool_size);
    memory_long(ucpool_size);
    memory_long(cpool_inuse);
    memory_long(ucpool_inuse);
    memory_long(real_avail);
    memory_long(bytes_coalesced);
    memory_long(bytes_coalesced_mempool);
    psectionend();
    memcpy(&mem_prev, &mem_now, sizeof(perfstat_memory_total_t) );
}


int    pagingspaces = 0;
perfstat_pagingspace_t *paging;

void    ps_paging_init()
{
    FUNCTION_START;
    if (danger) 
        return;
    /* check how many perfstat_pagingspace_t structures are available */
    DEBUG printf("ps_paging_init()\n");
    pagingspaces = perfstat_pagingspace(NULL, NULL, sizeof(perfstat_pagingspace_t), 0);

    ASSERT(pagingspaces > 0, "perfstat_pagingspace(init)", EXIT, pagingspaces);
    DEBUG printf("ps_paging_init() found %d\n", pagingspaces);

    if (pagingspaces > 0)
        paging = malloc( sizeof(perfstat_pagingspace_t) * pagingspaces);
}


void    ps_paging()
{
    int    rc;
    int    i;
    char    pagename[IDENTIFIER_LENGTH];

    FUNCTION_START;
    if (danger) 
        return;
    if (pagingspaces <= 0)
        return;

    pagename[0] = 0;
    rc = perfstat_pagingspace((perfstat_id_t * )pagename, paging, sizeof(perfstat_pagingspace_t), pagingspaces);
    /* return code is number of structures returned */
    DEBUG printf("ps_paging() found %d\n", rc);
    ASSERT(rc > 0, "perfstat_pagingspace(data)", RETURN, rc);
    if (rc <= 0) {  /* this is a work around for unexpected perfstat library behaviour = fails at second attempt */
        pagingspaces = 0;
        return;
    }
    psection("paging_spaces");
    for (i = 0; i < rc; i++) {
        psub(paging[i].name);
        if (paging[i].type == LV_PAGING) {
            pstring("type", "LV");
            pstring("vgname", paging[i].u.lv_paging.vgname);
        }
        if (paging[i].type == NFS_PAGING) {
            pstring("type", "NFS");
            pstring("hosname", paging[i].u.nfs_paging.hostname);
            pstring("filename", paging[i].u.nfs_paging.filename);
        }
        plong("lp_size", paging[i].lp_size);
        plong("mb_size", paging[i].mb_size);
        plong("mb_used", paging[i].mb_used);
        plong("io_pending", paging[i].io_pending);
        plong("active", paging[i].active);
        plong("automatic", paging[i].automatic);
        psubend();

    }
    psectionend();
}


void    filesystems()
{
    int    i;
    int    fd;
    struct fstab *fstab_buffer;
    struct stat stat_buffer;
    struct statfs64 statfs_buffer;
    double    fs_size_mb;
    double    fs_free_mb;
    double    fs_size_used;
    double    fs_inodes_used;

    FUNCTION_START;
    psection("filesystems");
    setfsent();
    for (i = 0; (fstab_buffer = getfsent() ) != NULL; i++) {
        if (stat(fstab_buffer->fs_file, &stat_buffer) != -1 ) {
            if (stat_buffer.st_flag & FS_MOUNT) {
                if ( (fd = open(fstab_buffer->fs_file, O_RDONLY)) != -1) {
                    if (fstatfs64( fd, &statfs_buffer) != -1) {
                        if (!strncmp(fstab_buffer->fs_spec, "/proc", 5)) { /* /proc gives invalid/insane values */
                            fs_size_mb = 0;
                            fs_free_mb = 0;
                            fs_size_used = 100.0;
                            fs_inodes_used = 100.0;
                        } else {
                            fs_size_mb = (double)statfs_buffer.f_blocks * (double)statfs_buffer.f_bsize / 1024.0 /1024.0;
                            fs_free_mb = (double)statfs_buffer.f_bfree  * (double)statfs_buffer.f_bsize / 1024.0 /1024.0;
                            fs_size_used = ((double)statfs_buffer.f_blocks - (double)statfs_buffer.f_bfree)
                             / (double)statfs_buffer.f_blocks * 100.0;
                            fs_inodes_used = ((double)statfs_buffer.f_files - (double)statfs_buffer.f_ffree)
                             / (double)statfs_buffer.f_files * 100.0;
                        }
                        psub(fstab_buffer->fs_file);
                        pstring("mount",  fstab_buffer->fs_file);
                        pstring("device", fstab_buffer->fs_spec);
                        pdouble("size_mb", fs_size_mb);
                        pdouble("free_mb", fs_free_mb);
			if(statfs_buffer.f_blocks >= statfs_buffer.f_bfree) { /* while using the old statfs structure */
                            pdouble("used_percent", fs_size_used);
                            pdouble("inode_percent", fs_inodes_used);
			}
                        plong("files_inuse", (double)statfs_buffer.f_files);
                        plong("files_free", (double)statfs_buffer.f_ffree);
                        plong("f_blocks", (long long)statfs_buffer.f_blocks);
                        plong("f_bfree",  (long long)statfs_buffer.f_bfree);
                        psubend();
                    } else {
                        nwarning2("fstatfs() of %s failed\n", fstab_buffer->fs_file);
                    }
                    close(fd);
                } else {
                    nwarning2("open(%s,O_RDONLY) failed\n", fstab_buffer->fs_file);
                }
            }
        } else {
            nwarning2("stat of %s failed errno=%d\n", fstab_buffer->fs_file);
        }
    }
    endfsent();
    psectionend();
}


/* Logical Volumes */
int    lvs = 1;
perfstat_logicalvolume_t *lv_stat;
perfstat_logicalvolume_t *lv_save;

void    ps_lv_init()
{
    int    rc;
    char    lv_name[IDENTIFIER_LENGTH];

    FUNCTION_START;
    if (lvs == 0) 
        return;

    perfstat_config(PERFSTAT_ENABLE | PERFSTAT_LV, NULL);
    /* find out the number of adapters */
    lv_name[0] = 0;
    lvs = perfstat_logicalvolume(NULL, NULL, sizeof(perfstat_logicalvolume_t), 0);
    ASSERT(lvs > 0, "perfstat_logicalvolume(init)", EXIT, lvs);

    lv_stat = malloc(sizeof(perfstat_logicalvolume_t) * lvs);
    ASSERT_PTR(lv_stat != NULL, "malloc", EXIT, lv_stat);

    lv_save = malloc(sizeof(perfstat_logicalvolume_t) * lvs);
    ASSERT_PTR(lv_save != NULL, "malloc", EXIT, lv_save);
    lv_name[0] = 0;
    rc = perfstat_logicalvolume((perfstat_id_t * )lv_name, lv_save, sizeof(perfstat_logicalvolume_t), lvs);
    if (rc == -1 && errno == 13) {
        /* errno = 13 means Permission denied */
        /* You have to be root user or equivalent to collect Logical Volume stats 
           I think this is because there are performance implications of switching on AIX trace */
        lvs = 0;
        return;
    }
    ASSERT(rc > 0, "perfstat_logicalvolume(save)", EXIT, rc);
}


void    ps_lv_stats(double elapsed)
{
    int    i;
    int    rc;
    char    lv_name[IDENTIFIER_LENGTH];
    char    string[512];

    FUNCTION_START;
    if (lvs == 0) 
        return;

    lv_name[0] = 0;
    rc = perfstat_logicalvolume((perfstat_id_t * )lv_name, lv_stat, sizeof(perfstat_logicalvolume_t), lvs);
    ASSERT(rc > 0, "perfstat_fcstat(data)", EXIT, rc);

    psection("logicalvolumes");
    for (i = 0; i < rc; i++) {
        psub(lv_stat[i].name);
        pstring("vgname",  lv_stat[i].vgname);
        plong("open_close", lv_stat[i].open_close);

        switch ((long)lv_stat[i].state) {
        case 0: 
            pstring("state", "Undefined=0"); 
            break;
        case 1: 
            pstring("state", "Defined=1"); 
            break;
        case 2: 
            pstring("state", "Stale=2"); 
            break;
        case 4: 
            pstring("state", "MirrorBackup=4"); 
            break;
        case 5: 
            pstring("state", "PassiveRecovery=5"); 
            break;

        default:
            sprintf(string, "unknown=%d", lv_stat[i].state);
            pstring("state", string); 
            break;
        }

        plong("mirror_policy",        lv_stat[i].mirror_policy);
        plong("mirror_write_consistency", lv_stat[i].mirror_write_consistency);
        plong("write_verify",         lv_stat[i].write_verify);
        plong("ppsize_mb",            lv_stat[i].ppsize);
        plong("logical_partitions",      lv_stat[i].logical_partitions);
        plong("mirrors",          lv_stat[i].mirrors);
        pdouble("iocnt",   ((double)(lv_stat[i].iocnt    - lv_save[i].iocnt)) / elapsed);
        pdouble("kbreads", ((double)(lv_stat[i].kbreads  - lv_save[i].kbreads)) / elapsed);
        pdouble("kbwrites", ((double)(lv_stat[i].kbwrites - lv_save[i].kbwrites)) / elapsed);
        psubend();
    }
    psectionend();
    memcpy(lv_save, lv_stat, sizeof(perfstat_logicalvolume_t) * lvs);
}


/* Volume Groups */
int    vgs = 1;
perfstat_volumegroup_t *vg_stat;
perfstat_volumegroup_t *vg_save;

void    ps_vg_init()
{
    int    rc;
    char    vg_name[IDENTIFIER_LENGTH];

    FUNCTION_START;
    if (vgs == 0) 
        return;

    perfstat_config(PERFSTAT_ENABLE | PERFSTAT_VG, NULL);
    /* find out the number of adapters */
    vg_name[0] = 0;
    vgs = perfstat_volumegroup(NULL, NULL, sizeof(perfstat_volumegroup_t), 0);
    ASSERT(vgs > 0, "perfstat_volumegroup(size)", EXIT, vgs);

    vg_stat = malloc(sizeof(perfstat_volumegroup_t) * vgs);
    ASSERT_PTR(vg_stat != NULL, "malloc", EXIT, vg_stat);

    vg_save = malloc(sizeof(perfstat_volumegroup_t) * vgs);
    ASSERT_PTR(vg_save != NULL, "malloc", EXIT, vg_save);
    vg_name[0] = 0;
    rc = perfstat_volumegroup((perfstat_id_t * )vg_name, vg_save, sizeof(perfstat_volumegroup_t), vgs);
    if (rc == -1 && errno == 13) {
        /* errno = 13 means Permission denied */
        /* You have to be root user or equivalent to collect Volumg Group stats 
           I think this is because there are performance implications of switching on AIX trace */
        vgs = 0;
        return;
    }
    ASSERT(rc > 0, "perfstat_volumegroup(save)", EXIT, rc);
}


void    ps_vg_stats(double elapsed)
{
    int    i;
    int    rc;
    char    vg_name[IDENTIFIER_LENGTH];

    FUNCTION_START;
    if (vgs == 0) 
        return;

    vg_name[0] = 0;
    rc = perfstat_volumegroup((perfstat_id_t * )vg_name, vg_stat, sizeof(perfstat_volumegroup_t), vgs);
    ASSERT(rc > 0, "perfstat_volumegroup(data)", EXIT, rc);

    psection("volumegroups");
    for (i = 0; i < rc; i++) {
        psub(vg_stat[i].name);
        plong("total_disks",        vg_stat[i].total_disks);
        plong("active_disks",       vg_stat[i].active_disks);
        plong("total_logical_volumes", vg_stat[i].total_logical_volumes);
        plong("opened_logical_volumes", vg_stat[i].opened_logical_volumes);

        pdouble("iocnt",   ((double)(vg_stat[i].iocnt    - vg_save[i].iocnt)) / elapsed);
        pdouble("kbreads", ((double)(vg_stat[i].kbreads  - vg_save[i].kbreads)) / elapsed);
        pdouble("kbwrites", ((double)(vg_stat[i].kbwrites - vg_save[i].kbwrites)) / elapsed);

        plong("variedState", vg_stat[i].variedState);
        psubend();
    }
    psectionend();
    memcpy(vg_save, vg_stat, sizeof(perfstat_volumegroup_t) * vgs);
}


int has_dots(char *name)
{
    int i;
    int len;
    int ret = 0;

        len = strlen(name);
        for (i = 0; i < len; i++) {
            if (name[i] == '.') {
		ret++;
            }
        }
	return ret;
}

void    get_hostname()
{
    static int    set = 0;
    int    i;
    int    dots = 0;
    int    len;
    struct hostent *he;

    FILE * pop;
    char   string[1024];
    char   hostn_command[1024];

    FUNCTION_START;
    if (set == 1)
        return;
    set = 1;

    strcpy(hostname,     "not-found");
    strcpy(fullhostname, "not.found");

    if ( gethostname(hostname, sizeof(hostname)) == 0) {
        strcpy(fullhostname, hostname);
        len = strlen(hostname);
        for (i = 0; i < len; i++) {  /* shorten the short name */
            if (hostname[i] == '.') {
                hostname[i] = 0;
                break;
            }
        }
	DEBUG printf("    hostname is \"%s\"\n", hostname);
	DEBUG printf("fullhostname is \"%s\"\n", fullhostname);
	if(has_dots(fullhostname) > 0) /* We did got a FQDN */
	    return;
    }
    if((he = gethostbyname(hostname)) != NULL) {
	DEBUG printf("gethostbyhostname \"%s\"\n", he->h_name);
	if(has_dots(he->h_name) > 0) { /* We did got a FQDN */
            strcpy(fullhostname,he->h_name);
    	    return;
        } 
    }

    sprintf(hostn_command, "host -n %s 2>/dev/null", hostname);
    if ( (pop = popen(hostn_command, "r") ) != NULL ) {
        if ( fgets(string, 1023, pop) != NULL) {
	    len = strlen(string);
	    for(i=0;i<len;i++) {
		if(string[i] == ' ') {
		    string[i] = 0;
		    break;
		}
	    }
	    DEBUG printf("\"%s\" returned first word of \"%s\"\n", hostn_command, string);
            if(has_dots(string))
	        strcpy(fullhostname,string);
        }
        pclose(pop);
    } 
}


void    identity()
{
    FILE * fp;
    char    buf[1024+1];
    int    i;
    /* user name and id */
    struct passwd *pw;
    uid_t uid;

    FUNCTION_START;
    get_hostname();
    psection("identity");
    if(fullhostname_tag)
        pstring("hostname", fullhostname);
    else
        pstring("hostname", hostname);
    pstring("fullhostname", fullhostname);
    pstring("njmon_command", njmon_command);
    pstring("njmon_mode", njmon_command);
    pstring("njmon_version", njmon_version);
    uid = geteuid();
    if (pw = getpwuid (uid)) {
        pstring("username", pw->pw_name);
        plong("userid", (long)uid);
    } else {
        pstring("username", "unknown");
        plong("userid", (long)-1);
    }
    psectionend();
}


void    hint()
{
char *progname;

    FUNCTION_START;
    if(mode == NJMON) 
	progname = "njmon";
    else
	progname = "nimon";
    printf("%s: help information. Version:%s\n\n", progname, njmon_version);
    if(mode == NJMON)
        printf("- Performance stats collector outputting JSON format. Default is stdout\n");
    if(mode == NIMON )
        printf("- Performance stats collector outputting Influx Line Protocol format. Default is stdout\n");
    printf("- Core syntax:     %s -s seconds -c count\n", progname);
    printf("- File output:     -m directory -f\n");
    printf("- Check & restart: -k\n");
    printf("- Data options:    -P -L -V -R -v -u -U -? -H -d\n");
    printf("- Argument file:   -a file\n");
    if(mode == NJMON)
        printf("- Network connection: -i host -p port\n");
    if(mode == NIMON) {
	printf("- Network connection: -i host -p port \n");
	printf("  InfluxDB Details  : -x database -y username -x password \n");
	printf("  Prometheus mode   : -w\n");
    }
    printf("\n");
    printf("\t-s seconds : seconds between snapshots of data (default 60 seconds)\n");
    printf("\t-c count   : number of snapshots then stop     (default forever)\n\n");
    printf("\t-m directory : Program will cd to the directory before output\n");
    printf("\t-f       : Output to file (not stdout) to two files below\n");
    if(mode == NIMON) {
        printf("\t         : Data:  hostname_<year><month><day>_<hour><minutes>.influxlp\n");
        printf("\t         : Note: a second -f adds a timestamp so this data can be added to InfluxDB later\n");
    }
    if(mode == NJMON)
        printf("\t         : Data:  hostname_<year><month><day>_<hour><minutes>.json\n");
    printf("\t         : Error: hostname_<year><month><day>_<hour><minutes>.err\n");
    printf("\t-I       : Set nimon mode for senting the data to InfluxDB or Telegraph\n");
    printf("\t-J       : Set njmon mode for JSON format for njmond.py or other Timeseries database\n");
    printf("\t-k       : Read /tmp/%s.pid for a running %s PID & if found running then this copy exits\n\n", progname, progname);
    printf("\t-K file    User defined pid filename (implies -k). Allows not using /tmp or\n"); 
    printf("\t           multiple concurrent data captures\n");
    printf("\t-a file  : Read the command line arguments from a file (so no passwords in ps output)\n");
    printf("\t         : Use the same arguments, all on the first line, space separated\n");
    printf("\t         : Only have the -a option on the actual command line\n");
    printf("\t-P       : Also collect process stats (these can be very large)\n");
    printf("\t-t p     : Process CPU cut-off threshold percent.   Default 0.001%\n");
    printf("\t-b       : Process stats switch of adding pid to the processnames: \"ksh_76927\" -> \"ksh\"\n");
    printf("\t-L       : Don't collect Logical Volume stats (takes extra CPU cycles)\n");
    printf("\t-V       : Don't collect Volume Group   stats (takes extra CPU cycles)\n");
    printf("\t           -L & -V requires root access. If not root these are silently switched off\n");
    printf("\t-R       : Don't collect CPU core thread: logical CPUs=cpu_logical/physical/syscall stats nor netbuffers\n");
    printf("\t-C       : Shared CPU/Processor Pool, you need to enable performance data collection (HMC)\n");
#ifdef VIOS
    printf("\t-v       : VIOS data on virtual disks, virtual FC and virtual networks\n");
#else
    printf("\t-v       : Note: VIOS options not included in this binary (-v will be ignored)\n");
#endif /* VIOS */
#ifdef SSP
    printf("\t-u       : VIOS SSP data like pool, pv and LU\n");
    printf("\t-U       : VIOS SSP data like -u plus VIOS cluster data\n");
    printf("\t          Warning this can add 2 seconds per VIOS in the SSP cluster\n");
#else
    printf("\t-U -u    : Note: SSP options compiled out of binary\n");
#endif /* SSP */
    printf("\t-?       : Output this help message and stop\n");
    printf("\t-h       : Same as -?\n");
    printf("\t-d       : Switch on debugging\n");
    printf("\t-o       : If using Oracle ASM raw disks have zero size, so use bootinfo -s to find the size.\n");
    printf("\t-r       : Random pause at the start. Stops cron starting every %s in sync.\n", progname);
    printf("\t-n       : No PID printed out at start up.\n");
    printf("\t-W       : Ignore warnings\n");
    if(mode == NJMON) {
        printf("Push data to collector:\n");
        printf("\t-i ip    : IP address or hostname of the njmon central collector\n");
        printf("\t-p port  : port number on collector host\n");
    }
    if(mode == NIMON) {
        printf("\t-H       : Force host tag to be a Fully Qualified Domain Name\n");
        printf("Sent data to InfluxDB:\n");
        printf("\t-i ip    : IP address or hostname of the IifluxDB\n");
        printf("\t-p 8086  : InfluxDB port (default is 8086)\n");
        printf("\t-x nimon : InfluxDB database name\n");
        printf("\t-y user  : InfluxDB username\n");
        printf("\t-z pass  : InfluxDB password\n");
    }
    printf("\tBits\n");
    if(mode == NJMON)
        printf("\t-e       : Create elastic server friedly output (arrays for subsections)\n");
    printf("\t-D       : Skip dangerous libperfstat function\n");
    printf("\n");
    printf("Examples:\n");
    if(mode == NJMON) {
        printf("    1 Every 5 mins all day into a file");
        printf("\tnjmon -s 300 -c 288 -f -m /home/perf\n");
        printf("    2 Piping to data handler using defaults -s60 forever\n");
        printf("\tnjmon | myprog\n");
        printf("    3 Add process stats and remove LV + VG data for an hour\n");
        printf("\tnjmon -s60 -c 60 -PLV > njmon.json\n");
        printf("    4 Collect daytime VIOS extra including SSP (if compiled in)\n");
        printf("\tnjmon -s60 -c 720 -vuU > njmon_on_vios.json\n");
        printf("    5 Crontab entry - 4 minutes after midnight save local data every 30 seconds\n");
        printf("\t4 0 * * * /usr/lbin/njmon -s 30 -c 2880 -f -m /home/perf\n");
        printf("    6 Crontab - hourly check/restart remote njmon, pipe stats back & insert into local DB\n");
        printf("\t0 * * * * /usr/lbin/ssh nigel@server /usr/lbin/njmon -k -s 300 -c 288 | /lbin/injector\n");
        printf("    7 Crontab - for pumping data to the central collector\n");
        printf("\t0 0 * * * /usr/lbin/njmon -s 300 -c 288 -i myadminhost -p 8181 -X SECRET42 \n");
    }
    if(mode == NIMON) {
        printf("    1 Every 1 minute all day using InfluxDB default port of 8086\n");
        printf("\tnimon -s 60 -c 1440 -i influxbox -x nimon -y Nigel -z passwd\n");
        printf("    2 Add process stats and Remove LV + VG data for an hour\n");
        printf("\tnimon -s60 -c 1440 -PLV -i influxbox -p 8086 -x nimon -y Nigel -z passwd\n");
        printf("    3 Collect VIOS extra including SSP (if compiled in)\n");
        printf("\tnimon -s30 -c 2880 -vuU -i influxbox -p 8086 -x nimon -y Nigel -z passwd\n");
        printf("    4 Crontab entry - 4 minutes after midnight save local data every 30 seconds\n");
        printf("\t4 0 * * * /usr/lbin/nimon -s30 -c 2880 -vuU -i influxbox -p 8086 -x nimon -y Nigel -z passwd >/dev/null\n");
        printf("    5 Crontab - hourly check/restart nimon (if failed)\n");
        printf("\t0 * * * * /usr/lbin/nimon -s 60 -k -i influxbox -p 8086 -x nimon -y Nigel -z passwd\n");
        printf("    6 Save the data to a file & take a look - this can not be loaded in to InfluxDB\n");
        printf("\tnimon -s1 -c 3 -m /tmp -f\n");
        printf("    7 Send data to telegraf and then onto prometheus\n");
        printf("\tnimon -s 15 -c 5760 -w -i telegraf_server -p 8888\n");
        printf("    8 Using -a argument-file option: /usr/lbin/nimon -a /etc/njmon.conf\n");
        printf("\t/etc/njmon.config file contains for example:\n\t-s 60 -c 1440 -i influxbox -p 8086 -x nimon -y Nigel -z passwd\n");
    }
    printf("\ncrontab Reminder: minute(0-59) hour(0-23) day_of_month(1-31) month(1-12) weekday(0-6=Sunday-Saturday) command\n");
}


/* See /usr/include/sys/iplcb.h to explain the below */
#define XINTFRAC    ((double)(_system_configuration.Xint)/(double)(_system_configuration.Xfrac))

/* hardware ticks per millisecond */
#define HWTICS2MSECS(x)    (((double)x * XINTFRAC)/1000000.0)

#ifndef FIRST_DISK
#define FIRST_DISK ""
#endif

char    *fix(char *s) /* Removes odd punctuation from names */
{
    int    j;
    FUNCTION_START;
    for (j = 0; j < IDENTIFIER_LENGTH; j++) {
        if (s[j] == 0) 
            break;
        if (s[j] == '\\') 
            s[j] = '?' ;
        if (s[j] == ' ')    
            continue;
        if (isalpha(s[j])) 
            continue;
        if (isdigit(s[j])) 
            continue;
        if (ispunct(s[j])) 
            continue;
        s[j] = '?' ;
    }
    return s;
}


int    disks;
perfstat_disk_t *diskprev;
perfstat_disk_t *diskcurr;

void    ps_disk_flush_minmax()
{
    int rc;

    rc = perfstat_partial_reset(NULL, RESET_DISK_MINMAX);
    ASSERT(rc == 0, "perfstat_partial_reset(MINMAX)", EXIT, rc);
}

void    ps_disk_init()
{
    int    rc;
    char    disk_name[IDENTIFIER_LENGTH];

    FUNCTION_START;
    if (danger) 
        return;
    rc = perfstat_partial_reset(NULL, FLUSH_DISK | RESET_DISK_MINMAX);
    ASSERT(rc == 0, "perfstat_partial_reset()", EXIT, rc);

    /* check how many perfstat_disk_t structures are available */
    disks = perfstat_disk(NULL, NULL, sizeof(perfstat_disk_t), 0);
    ASSERT(disks > 0, "perfstat_disk(init)", EXIT, disks);

    /* allocate enough memory for all the structures */
    diskprev = malloc( sizeof(perfstat_disk_t) * disks);
    ASSERT_PTR(diskprev != NULL, "malloc(diskprev)", EXIT, diskprev);

    diskcurr = malloc( sizeof(perfstat_disk_t) * disks);
    ASSERT_PTR(diskcurr != NULL, "malloc(diskcurr)", EXIT, diskcurr);

    /* ask to get all the structures available in one call */
    /* return code is number of structures returned */
    disk_name[0] = 0;
    rc = perfstat_disk((perfstat_id_t * )disk_name, diskprev, sizeof(perfstat_disk_t), disks);
    ASSERT(rc > 0, "perfstat_disk(init again)", EXIT, rc);
    /* printf("Found %d disks\n",rc); */
}


void    ps_one_disk(perfstat_disk_t curr, perfstat_disk_t prev, double elapsed)
{
    long    size = -1;
    FILE * pop;
    char    string[256 +1];

    FUNCTION_START;
    psub(fix(curr.name));
    if( strlen(curr.description) > 0)
        pstring("description", fix(curr.description));
    if( strlen(curr.vgname) > 0)
        pstring("vg", fix(curr.vgname));
    plong("blocksize",  curr.bsize);

#define DISK_DELTA(member) ((double)curr.member - (double)prev.member)

    if ( curr.size == 0 && oracle ) {
        /* This could be an Oracle ASM disk where the size goes missing
         *     but the read / write stats still seems to work.
         * We found the if root user "bootinfo -s hdiskX" command gets the size anyway.
         * bootinfo is very fast = less than 0.01 seconds
         */
        sprintf(string, "/usr/sbin/bootinfo -s %s 2>/dev/null", curr.name);
        if ( (pop = popen(string, "r") ) != NULL ) {
            if ( fgets(string, 256, pop) != NULL) {
                size = atol(string);
            }
            pclose(pop);
        }
        plong("size_mb", size);
    } else {
        plong("size_mb", curr.size);
    }
    plong("free_mb",     curr.free);
    pdouble("xrate_read", DISK_DELTA(xrate) / elapsed);
    pdouble("xfers",      DISK_DELTA(xfers) / elapsed);
    pdouble("read_blks",  DISK_DELTA(rblks) / (double)elapsed);
    pdouble("write_blks", DISK_DELTA(wblks) / (double)elapsed);
    pdouble("read_mbps",  (double)DISK_DELTA(rblks) * (double)curr.bsize / (1024.0 * 1024.0 ) / elapsed); /* before v74 these were KBps  Oops! */
    pdouble("write_mbps", (double)DISK_DELTA(wblks) * (double)curr.bsize / (1024.0 * 1024.0 ) / elapsed);
    pdouble("busy",       (double)DISK_DELTA(time) / (double)elapsed);
    plong("qdepth",      curr.qdepth);

#define NONZERO(x) ((x)?(x):1)

    /* skip cd{n} CD drives */
    if ( !( curr.name[0] == 'c' && curr.name[1] == 'd' && isdigit(curr.name[2]) ) ) {
	/*
         * pdouble("rserv_min", curr.min_rserv);
         * pdouble("rserv_max", curr.max_rserv);
	 */
        pdouble("rserv_min", (double)(HWTICS2MSECS(curr.min_rserv)));
        pdouble("rserv_max", (double)(HWTICS2MSECS(curr.max_rserv)));
        pdouble("rserv_avg", (double)(HWTICS2MSECS(DISK_DELTA(rserv)) / NONZERO(DISK_DELTA(__rxfers))));
        plong("rtimeout",  curr.rtimeout);
        plong("rfailed",   curr.rfailed);
	/*
         * pdouble("wserv_min", curr.min_wserv);
         * pdouble("wserv_max", curr.max_wserv);
	 */
        pdouble("wserv_min", (double)(HWTICS2MSECS(curr.min_wserv)));
        pdouble("wserv_max", (double)(HWTICS2MSECS(curr.max_wserv)));
        pdouble("wserv_avg", (double)(HWTICS2MSECS(DISK_DELTA(wserv)) / (NONZERO( DISK_DELTA(xfers) - DISK_DELTA(__rxfers)))));
        plong("wtimeout",  curr.wtimeout);
        plong("wfailed",   curr.wfailed);
	/* 
         * pdouble("wqueue_time_min", curr.wq_min_time);
         * pdouble("wqueue_time_max", curr.wq_max_time);
	 */
        pdouble("wqueue_time_min", (double)(HWTICS2MSECS(curr.wq_min_time)));
        pdouble("wqueue_time_max", (double)(HWTICS2MSECS(curr.wq_max_time)));
        pdouble("wqueue_time_avg", (double)(HWTICS2MSECS(DISK_DELTA(wq_time)) / NONZERO(DISK_DELTA(xfers))));

        pdouble("avgWQsz", (double)(DISK_DELTA(wq_sampled)) / (100.0 * (double)elapsed * (double)cpu_total));
        pdouble("avgSQsz", (double)(DISK_DELTA(q_sampled)) / (100.0 * (double)elapsed * (double)cpu_total));
        plong("SQfull", DISK_DELTA(q_full));
        plong("wq_depth", curr.wq_depth);
    }
    psubend();

#ifdef RAWSTATS
    sprintf(string, "%s_raw", fix(curr.name));
    psub(string);
    if( strlen(curr.description) > 0)
        pstring("description", fix(curr.description));
    if( strlen(curr.vgname) > 0)
        pstring("vg", fix(curr.vgname));
    plong("blocksize",  curr.bsize);

    plong("size_mb", curr.size);
    plong("free_mb",    curr.free);
    plong("xrate_read", curr.xrate);
    plong("xfers",      curr.xfers);
    plong("read_blks",  curr.rblks);
    plong("write_blks", curr.wblks);
    plong("read_mbps",  curr.rblks);
    plong("write_mbps", curr.wblks);
    plong("busy",       curr.time);
    plong("qdepth",     curr.qdepth);

    /* skip cd{n} CD drives */
    if ( !( curr.name[0] == 'c' && curr.name[1] == 'd' && isdigit(curr.name[2]) ) ) {
        plong("rserv_min", curr.min_rserv);
        plong("rserv_max", curr.max_rserv);
        plong("rserv_avg", curr.rserv);
        plong("rtimeout",  curr.rtimeout);
        plong("rfailed",   curr.rfailed);

        plong("wserv_min", curr.min_wserv);
        plong("wserv_max", curr.max_wserv);
        plong("wtimeout",  curr.wtimeout);
        plong("wfailed",   curr.wfailed);

        plong("wqueue_time_min", curr.wq_min_time);
        plong("wqueue_time_max", curr.wq_max_time);

        plong("avgWQsz", curr.wq_sampled);
        plong("avgSQsz", curr.q_sampled);
        plong("SQfull", curr.q_full);
        plong("wq_depth", curr.wq_depth);
    }
    psubend();

#endif /* RAWSTATS */
}


void    ps_disk_stats(double elapsed)
{
    int    i;
    int    j;
    int    rc;
    char    diskname[IDENTIFIER_LENGTH];

    FUNCTION_START;
    if (danger) 
        return;
    if (disks == 0) 
        return;
    diskname[0] = 0;
    rc = perfstat_disk((perfstat_id_t * )diskname, diskcurr, sizeof(perfstat_disk_t), disks);
    /* printf("disks=%d, rc=%d\n", disks, rc); */
    ASSERT(rc > 0, "perfstat_disk(data)", RETURN, rc);
    if (rc <= 0) {
        disks = 0;
        return;
    }

    psection("disks");
    for (i = 0; i < disks; i++) {
        ps_one_disk(diskcurr[i], diskprev[i], elapsed);
    }
    psectionend();
    memcpy(diskprev, diskcurr, sizeof(perfstat_disk_t) * disks );
}


#ifdef VIOS
int    targets;
perfstat_disk_t *targetprev;
perfstat_disk_t *targetcurr;

void    ps_vios_target_init()
{
    int    rc;
    char    target_name[IDENTIFIER_LENGTH];

    FUNCTION_START;
    /* check how many perfstat_disk_t structures are available */
    targets = perfstat_virtualdisktarget(NULL, NULL, sizeof(perfstat_disk_t), 0);
    ASSERT(targets >= 0, "perfstat_disk(init)", RETURN, targets);

    if (targets <= 0) {
        vios_vhosts = 0;
        return;
    }
    /* allocate enough memory for all the structures */
    targetprev = malloc( sizeof(perfstat_disk_t) * targets);
    ASSERT_PTR(targetprev != NULL, "malloc(tartgetprev)", EXIT, targetprev);
    targetcurr = malloc( sizeof(perfstat_disk_t) * targets);
    ASSERT_PTR(targetcurr != NULL, "malloc(tartgetcurr)", EXIT, targetcurr);

    /* ask to get all the structures available in one call */
    /* return code is number of structures returned */
    target_name[0] = 0;
    rc = perfstat_virtualdisktarget((perfstat_id_t * )target_name, targetprev, sizeof(perfstat_disk_t), targets);
    ASSERT(rc > 0, "perfstat_virtualdisktarget(init again)", EXIT, rc);
    DEBUG printf("Found %d virtualdisktargets\n", rc);
}


void    ps_vios_target_stats(double elapsed)
{
    int    i;
    int    rc;
    char    targetname[IDENTIFIER_LENGTH];

    FUNCTION_START;
    if (targets == 0) 
        return;
    targetname[0] = 0;
    rc = perfstat_virtualdisktarget((perfstat_id_t * )targetname, targetcurr, sizeof(perfstat_disk_t), targets);
    ASSERT(rc > 0, "perfstat_virtualtargetadapter(init)", RETURN, rc);
    if (rc <= 0) {
        targets = 0;
        return;
    }

    psection("vios_disk_target");
    for (i = 0; i < rc; i++) {
        ps_one_disk(targetcurr[i], targetprev[i], elapsed);
    }
    psectionend();
    memcpy(targetprev, targetcurr, sizeof(perfstat_disk_t) * targets);
}


#endif /* VIOS */

perfstat_disk_total_t disktotal_a;
perfstat_disk_total_t disktotal_b;

void    ps_disk_total_init()
{
    int    rc;
    char    disktot_name[IDENTIFIER_LENGTH];

    FUNCTION_START;
    /* ask to get all the structures available in one call */
    /* return code is number of structures returned */
    disktot_name[0] = 0;
    rc = perfstat_disk_total(NULL, &disktotal_a, sizeof(perfstat_disk_total_t), 1);
    ASSERT(rc > 0, "perfstat_disk_total(init)", EXIT, rc);

    /* Repeat this  request: 
	I suspect libperfstat first supplies sum since booting stats.
	Also seen every 4th or 5th of these stats returns massive numbers but the rest are OK.
    */
    rc = perfstat_disk_total(NULL, &disktotal_a, sizeof(perfstat_disk_total_t), 1);
    ASSERT(rc > 0, "perfstat_disk_total(init)", EXIT, rc);
}


#define DISKTOTAL_DELTA(member) (disktotal_b.member - disktotal_a.member)

void    ps_disk_total_stats(double elapsed)
{
    int    rc;
    char    disktot_name[IDENTIFIER_LENGTH];

    FUNCTION_START;
    disktot_name[0] = 0;
    rc = perfstat_disk_total(NULL, &disktotal_b, sizeof(perfstat_disk_total_t), 1);
    ASSERT(rc > 0, "perfstat_disktotal(data)", EXIT, rc);

    psection("disk_total");
    plong("disks", disktotal_b.number);
    plong("size",  disktotal_b.size);
    plong("free",  disktotal_b.free);
    pdouble("xrate_read", DISKTOTAL_DELTA(xrate) / elapsed);
    pdouble("xfers",      DISKTOTAL_DELTA(xfers) / elapsed);
    pdouble("read_blks",  DISKTOTAL_DELTA(rblks) / (double)elapsed);
    pdouble("write_blks", DISKTOTAL_DELTA(wblks) / (double)elapsed);
    pdouble("time",       DISKTOTAL_DELTA(time) / elapsed);
    pdouble("rserv", (double)(HWTICS2MSECS(DISKTOTAL_DELTA(rserv)) / NONZERO(DISKTOTAL_DELTA(xrate))));
    pdouble("wserv", (double)(HWTICS2MSECS(DISKTOTAL_DELTA(wserv)) / NONZERO(DISKTOTAL_DELTA(xfers) - DISKTOTAL_DELTA(xrate))));
    pdouble("rtimeout",   DISKTOTAL_DELTA(rtimeout) / elapsed);
    pdouble("wtimeout",   DISKTOTAL_DELTA(wtimeout) / elapsed);
    pdouble("rfailed",    DISKTOTAL_DELTA(rfailed) / elapsed);
    pdouble("wfailed",    DISKTOTAL_DELTA(wfailed) / elapsed);
    pdouble("wq_time", (double)(HWTICS2MSECS(DISKTOTAL_DELTA(wq_time)) / NONZERO(DISKTOTAL_DELTA(xfers))));
    plong("wq_depth", disktotal_b.wq_depth);
    psectionend();
    memcpy(&disktotal_a, &disktotal_b, sizeof(perfstat_disk_total_t));
}


int    netbuffs = 0;
perfstat_netbuffer_t *netbuffs_stat;

void    ps_netbuffs_init()
{
    FUNCTION_START;
    if (danger) 
        return;
    netbuffs =  perfstat_netbuffer(NULL, NULL, sizeof(perfstat_netbuffer_t), 0);
    ASSERT(netbuffs > 0, "perfstat_netbuffer(init)", RETURN, netbuffs);
    if (netbuffs <= 0) { /* check for error */
        netbuffs = 0;
        return;
    }

    /* allocate enough memory for all the structures */
    netbuffs_stat = calloc(netbuffs, sizeof(perfstat_netbuffer_t));
    ASSERT_PTR(netbuffs_stat != NULL, "perfstat_netbuffer(calloc)", RETURN, netbuffs_stat);
    if (netbuffs_stat == NULL) {
        netbuffs = 0;
        return;
    }

}


void    ps_netbuffs()
{
    static perfstat_id_t first;
    int    ret, i;
    char    name[256];

    FUNCTION_START;
    if (danger) 
        return;
    if (netbuffs == 0) { /* then init failed so skip */
        return;
    }

    /* set name to first interface */
    strcpy(first.name, FIRST_NETBUFFER);

    /* ask to get all the structures available in one call */
    /* return code is number of structures returned */
    ret = perfstat_netbuffer(&first, netbuffs_stat, sizeof(perfstat_netbuffer_t), netbuffs);

    ASSERT(ret > 0, "perfstat_netbuffer(data)", RETURN, ret);
    /* check for error */
    if (ret <= 0) {
        netbuffs = 0;
        return;
    }
    psection("netbuffers");
    for (i = 0; i < ret; i++) {
        sprintf(name, "size%s", netbuffs_stat[i].name);
        psub(name);
        plong("inuse", netbuffs_stat[i].inuse);
        plong("calls", netbuffs_stat[i].calls);
        plong("delayed", netbuffs_stat[i].delayed);
        plong("free", netbuffs_stat[i].free);
        plong("failed", netbuffs_stat[i].failed);
        plong("highwatermark", netbuffs_stat[i].highwatermark);
        plong("freed", netbuffs_stat[i].freed);
        psubend();
    }
    psectionend("netbuffers");
}


/* LPAR */
#include <sys/dr.h>

lpar_info_format1_t f1;
lpar_info_format2_t f2;
lpar_info_format2_t f2_prev;

void    dr_lpar_init()
{
    int    rc;

    FUNCTION_START;
    rc = lpar_get_info(LPAR_INFO_FORMAT2, &f2_prev, sizeof(f2_prev));
    ASSERT(rc == 0, "lpar_get_info(f2_prev)", EXIT, rc);
}


void    dr_lpar_stats()
{
    int    i;
    int    rc;
    int    tot;

    unsigned long long    dispatch_wheel_time;

    /* Not clear how this compares with uptime values or how to use there stats 
     * lpar_load_t load;
     * rc=getlparload(&load,sizeof(lpar_load_t));
     * printf("\nlpar_load returned=%d loadavg=%d utilavg=%d shift=%d\n",rc,load.loadavg,load.utilavg,(int)load.loadavgshift);
     */

    FUNCTION_START;
    rc = lpar_get_info(LPAR_INFO_FORMAT1, &f1, sizeof(f1));
    ASSERT(rc == 0, "lpar_get_info(f1)", EXIT, rc);

    psection("lpar_format1");

#define printf1(xxx)    plong(   # xxx, (long long)f1.xxx);
#define printf1percent(xxx)     pdouble( # xxx, (double)f1.xxx/ 100.0);
#define printf1_string(xxx) pstring( # xxx, (char *)f1.xxx);

    printf1_string(lpar_name);
    printf1(min_memory);
    printf1(max_memory);
    printf1(memory_region);
    printf1(dispatch_wheel_time);

    dispatch_wheel_time = f1.dispatch_wheel_time;

    printf1(lpar_number);
    printf1(lpar_flags);
    printf1(max_pcpus_in_sys);
    printf1(min_vcpus);
    printf1(max_vcpus);
    printf1(min_lcpus);
    printf1(max_lcpus);
    printf1percent(minimum_capacity);
    printf1percent(maximum_capacity);
    printf1percent(capacity_increment);
    printf1(smt_threads);
#ifndef AIX6 /* these are missing on AIX 6 */
    printf1(num_lpars);
    printf1(servpar_id);
#endif /* AIX6 */
    printf1percent(desired_capacity);
    printf1(desired_vcpus);
    printf1(desired_memory);
    printf1(desired_variable_capwt);
    printf1(true_max_memory);
    printf1(true_min_memory);
    printf1(ame_max_memory);
    printf1(ame_min_memory);
    printf1(spcm_status);
    printf1(spcm_max);

    psectionend();

    rc = lpar_get_info(LPAR_INFO_FORMAT2, &f2, sizeof(f2));
    ASSERT(rc == 0, "lpar_get_info(f2)", EXIT, rc);

    psection("lpar_format2");

#define printf2(xxx)    plong( # xxx, (long long)f2.xxx);
#define printf2percent(xxx) pdouble( # xxx, (double)f2.xxx / 100.0);
#define printf2_hex(xxx)    phex( # xxx, (long long)f2.xxx);
#define printf2_rate(xxx)   plong( # xxx, ( (double)(f2.xxx - f2_prev.xxx) ) / (double)f1.dispatch_wheel_time  );

    printf2(online_memory);
    printf2_rate(tot_dispatch_time);
    /* 
     * printf("tot_dispatch_time=%lld prev=%lld delta=%lld dispatch_wheel_time=%lld cpu=%.1f\n",
     *     f2.tot_dispatch_time, f2_prev.tot_dispatch_time, f2.tot_dispatch_time - f2_prev.tot_dispatch_time, f1.dispatch_wheel_time,
     * (double)(f2.tot_dispatch_time - f2_prev.tot_dispatch_time)/(double)f1.dispatch_wheel_time);
     */

    printf2_rate(pool_idle_time);
    printf2(dispatch_latency);
    printf2_hex(lpar_flags); /* actually a hexadecimal flag */
    printf2(pcpus_in_sys);
    printf2(online_vcpus);
    printf2(online_lcpus);
    printf2(pcpus_in_pool);
    printf2(unalloc_capacity);
    printf2percent(entitled_capacity);
    printf2(variable_weight);
    printf2(unalloc_weight);
    printf2(min_req_vcpu_capacity);
    printf2(group_id);
    printf2(pool_id);
    printf2(shcpus_in_sys);
    printf2percent(max_pool_capacity);
    printf2percent(entitled_pool_capacity);
    printf2_rate(pool_max_time);
    printf2_rate(pool_busy_time);
    printf2_rate(pool_scaled_busy_time);
    printf2_rate(shcpu_tot_time);
    printf2_rate(shcpu_busy_time);
    printf2_rate(shcpu_scaled_busy_time);
    printf2(ent_mem_capacity);
    printf2(phys_mem);
    printf2(vrm_pool_physmem);
    printf2(hyp_pagesize);
    printf2(vrm_pool_id);
    printf2(vrm_group_id);
    printf2(var_mem_weight);
    printf2(unalloc_var_mem_weight);
    printf2(unalloc_ent_mem_capacity);
    printf2(true_online_memory);
    printf2(ame_online_memory);
    printf2(ame_type);
    printf2(ame_factor);
    printf2(em_part_major_code);
    printf2(em_part_minor_code);
    printf2(bytes_coalesced);
    printf2(bytes_coalesced_mempool);
    printf2(purr_coalescing);
    printf2(spurr_coalescing);
    psectionend(); /* Final section */

    memcpy(&f2_prev, &f2, sizeof(f2));
}


#ifdef SSP
perfstat_ssp_t *ssp_global;
perfstat_ssp_t *ssp_disk;
perfstat_ssp_t *ssp_lu;
perfstat_ssp_t *ssp_node;

int    global_count;
int    disk_count;
int    lu_count;
int    node_count;

int    ssp_mode = 0;       /* collect basic SSP data pool, disk, LU */
int    ssp_node_mode = 0;  /* collect SSP cluster data, can take 2 seconds per VIOS */

void    ps_ssp_init()
{
    FUNCTION_START;
    /* Enable the VIOS SSP cluster statistics */
    if ( perfstat_config(PERFSTAT_ENABLE | PERFSTAT_CLUSTER_STATS, NULL) < 0) {
        nwarning("perfstat_config SSP is not available. Only run this on a VIOS 2.2.6+ with a Shared Storeage Pool\n");
        ssp_mode = 0;
        ssp_node_mode = 0;
        return;
    }

    /* Determine the numbers of stats available */
    if ( (global_count = perfstat_ssp(NULL, NULL, sizeof(perfstat_ssp_t), 0, SSPGLOBAL) ) < 0) {
        nwarning("perfstat_ssp(global init)\n");
        ssp_mode = 0;
        ssp_node_mode = 0;
        return;
    }
    if ( (disk_count = perfstat_ssp(NULL, NULL, sizeof(perfstat_ssp_t), 0, SSPDISK) ) < 0) {
        nwarning("perfstat_ssp(disk init)");
        ssp_mode = 0;
        ssp_node_mode = 0;
        return;
    }
    if ( (lu_count = perfstat_ssp(NULL, NULL, sizeof(perfstat_ssp_t), 0, SSPVTD) ) < 0) {
        nwarning("perfstat_ssp(lu init)\n");
        ssp_mode = 0;
        ssp_node_mode = 0;
        return;
    }

    /* Prepare memory buffers */
    ssp_global = (perfstat_ssp_t * ) malloc(sizeof(perfstat_ssp_t) * global_count);
    ssp_disk   = (perfstat_ssp_t * ) malloc(sizeof(perfstat_ssp_t) * disk_count);
    ssp_lu     = (perfstat_ssp_t * ) malloc(sizeof(perfstat_ssp_t) * lu_count);
    if (ssp_global == (perfstat_ssp_t * )NULL || ssp_disk == (perfstat_ssp_t * )NULL || ssp_lu == (perfstat_ssp_t *
        )NULL ) {
        nwarning("malloc failure requesting space to store perfstat data\n");
        ssp_mode = 0;
        ssp_node_mode = 0;
    }
}


void    ps_ssp()
{
    int    i;
    int    rc;
    char    string[1024];

    FUNCTION_START;
    if ( (rc = perfstat_ssp(NULL, ssp_global, sizeof(perfstat_ssp_t), global_count, SSPGLOBAL) ) < 0) {
        nwarning("perfstat_ssp(SSPGLOBAL)\n");
        ssp_mode = 0;
        ssp_node_mode = 0;
        return;
    }

    psection("ssp_global");
    pstring("ClusterName",  ssp_global->cluster_name);
    pstring("PoolName",     ssp_global->spool_name);
    plong("TotalSpace_MB",     ssp_global->u.global.total_space);
    plong("TotalUsedSpace_MB", ssp_global->u.global.total_used_space);
    psectionend();

    if ( (rc = perfstat_ssp(NULL, ssp_disk, sizeof(perfstat_ssp_t), disk_count, SSPDISK) ) < 0) {
        nwarning("perfstat_ssp(SSPDISK)\n");
        ssp_mode = 0;
        ssp_node_mode = 0;
        return;
    }

    psection("ssp_pv");
    for (i = 0; i < rc; i++) {
        psub(ssp_disk[i].u.disk.diskname);
        plong("capacity_MB",    ssp_disk[i].u.disk.capacity);
        plong("free_MB",     ssp_disk[i].u.disk.free);
        pstring("tiername",     ssp_disk[i].u.disk.tiername);
        pstring("failure_group", ssp_disk[i].u.disk.fgname);
        psubend();
    }
    psectionend();

    if ( (rc = perfstat_ssp(NULL, ssp_lu, sizeof(perfstat_ssp_t), lu_count, SSPVTD) ) < 0) {
        nwarning("perfstat_ssp(SSPLU)\n");
        ssp_mode = 0;
        ssp_node_mode = 0;
        return;
    }

    psection("ssp_lu");
    for (i = 0; i < rc; i++) {
        psub(ssp_lu[i].u.vtd.lu_name);
        pstring("type",      ssp_lu[i].u.vtd.lu_type);
        plong("size_MB",     ssp_lu[i].u.vtd.lu_size);
        plong("free_MB",     ssp_lu[i].u.vtd.lu_free);
        plong("usage_MB",       ssp_lu[i].u.vtd.lu_usage);
        plong("client_LPAR_id", ssp_lu[i].u.vtd.client_id);
        pstring("MTM",       ssp_lu[i].u.vtd.mtm);
        pstring("VTDname",      ssp_lu[i].u.vtd.vtd_name);
        pstring("DRCname",      ssp_lu[i].u.vtd.drcname);
        pstring("udid",      ssp_lu[i].u.vtd.lu_udid);
        psubend();
    }
    psectionend();
}


void    ps_ssp_node_init()
{
    FUNCTION_START;
    if ( (node_count     = perfstat_ssp(NULL, NULL, sizeof(perfstat_ssp_t), 0, SSPNODE) ) <= 0) {
        nwarningd("perfstat_ssp(node init)failed returned %d\n", (long long)node_count);
        ssp_node_mode = 0;
        return;
    }

    if ( (ssp_node   = (perfstat_ssp_t * ) malloc(sizeof(perfstat_ssp_t) * node_count)) == (perfstat_ssp_t * )NULL ) {
        nwarningd("perfstat_ssp(malloc) failed returned %d\n", (long long)node_count);
        ssp_node_mode = 0;
    }
}


void    ps_ssp_node()
{
    int    i;
    int    rc;

    if ( (rc = perfstat_ssp(NULL, ssp_node, sizeof(perfstat_ssp_t), node_count, SSPNODE) ) < 0) {
        nwarningd("perfstat_ssp(SSPNODE) failed returned %d\n", (long long)rc);
        ssp_node_mode = 0;
        return;
    }

    psection("ssp_node");
    for (i = 0; i < rc; i++) {
        psub(ssp_node[i].u.node.hostname);
        pstring("ipaddress",  ssp_node[i].u.node.ip);
        pstring("MTMS",       ssp_node[i].u.node.mtms);
        plong("lparid",       ssp_node[i].u.node.lparid);
        pstring("ioslevel",   ssp_node[i].u.node.ioslevel);
        pstring("status",     (ssp_node[i].u.node.status == 1 ? "OK" : "-"));
        pstring("poolstatus", (ssp_node[i].u.node.poolstatus == 1 ? "OK" : "-"));
        psubend();
    }
    psectionend();
}
#endif /* SSP */

/* check_pid_file() and make_pid_file()
   If you start njmon and it finds there is a copy running already then it will quitely stop.
   You can hourly start njmon via crontab and not end up with dozens of copies runnings.
   It also means if the server reboots then njmon start in the next hour.
    Side-effect: it creates a file called /tmp/njmon.pid
*/

char    *pid_filename = NULL;

void    make_pid_file()
{
    int    fd;
    int    ret;
    char    buffer[32];

    FUNCTION_START;
    if ((fd = creat(pid_filename, O_CREAT | O_WRONLY)) < 0) {
        DEBUG printf("can't open new file for writing fd=%d\n", fd);
        DEBUG perror("open");
        return; /* no file */
    }
    DEBUG printf("write file descriptor=%d\n", fd);
    sprintf(buffer, "%ld \n", getpid() );
    DEBUG printf("write \"%s\"\n", buffer);
    if ((ret = write(fd, buffer, strlen(buffer))) <= 0)
        printf("write failed ret=%d\n", ret);
    close(fd);
}

void check_pid_file()
{
    char *ep;
    char buffer[32];
    int fd;
    pid_t pid;
    int ret;
    char *strptr;

    FUNCTION_START;
    if(pid_filename == NULL) {
	if(mode == NJMON)
	    strptr = "NJMON_PID_FILE";
	else
	    strptr = "NIJMON_PID_FILE";
        ep = getenv(strptr);
        if (ep == NULL) {               /* not in the environment, so use default */
		if(mode == NJMON)
		    pid_filename = "/tmp/njmon.pid";
		else
		    pid_filename = "/tmp/nimon.pid";
	} else {                        /* in the environment but getenv data not safe */
            pid_filename = malloc(strlen(ep) + 1);
            strcpy(pid_filename,ep);
        }
    }
    DEBUG printf("pid_file=%s\n", pid_filename);

    if( access( pid_filename, F_OK ) != -1 ) {
        printf("file exists\n");
        if ((fd = open(pid_filename, O_RDONLY)) < 0) {
            printf("njmon Warning %s files exists but no access:\n\tWrong owner or no permission.\n");
            perror("njmon stopping");
            exit(42);
        }

        if (read(fd, buffer, 31) > 0) { /* has some data */
        DEBUG printf("file has some content\n");
        buffer[31] = 0;
          if (sscanf(buffer, "%d", &pid) == 1) {
            DEBUG printf("read a pid from the file OK = %d\n", pid);
            ret = kill(pid, 0);         /* kiil with signal=0 does not kill the process ever */
            DEBUG printf("kill %d, 0) = returned =%d\n", pid, ret);
            if (ret == 0) {
                DEBUG printf ("We have nimon or njmon running - exit quietly\n");
                exit(99);
            }
          }
        }
        /* if we got here there is a file but the content is duff or the process is not running */
        close(fd);
        remove(pid_filename);
    }
}

void    remove_pid_file()
{
    FUNCTION_START;
    if(pid_filename != 0)
	remove(pid_filename);
}


struct rperf_struct {
	char mtm[20];
	double mhz;
	int stats;
	struct  {
		int cpus;
		double rperf;
	} match[16];
} rperf_data[] = 
{
	/* POWER6 */
        /* # JS12 and JS22 Blades */
        "IBM-7998-60X", 3800.0, 1, {{ 2, 14.71 } },
        "IBM-7998-61X", 4000.0, 1, {{ 4, 30.26 } },
        /* # 520 */
        "IBM-8203-E4A", 4200.0, 3, {{ 1,  8.39}, { 2, 15.95}, {  4, 31.48 } },
        /* # 550 */
        "IBM-8204-E8A", 3500.0, 4, {{ 2, 15.85}, { 4, 31.27}, {  6, 45.04}, { 8, 58.80 } },
        "IBM-8204-E8A", 4200.0, 4, {{ 2, 18.38}, { 4, 36.28}, {  6, 52.24}, { 8, 68.20 } },
        /* # 570 */
        "IBM-9117-MMA", 3500.0, 5, {{ 2, 15.85}, { 4, 31.69}, {  8, 58.95}, { 12, 83.35}, { 16, 105.75 } },
        /* # POWER6+ */
        "IBM-9117-MMA", 4200.0, 5, {{ 4, 35.50}, { 8, 64.96}, { 16, 113.68}, { 24, 153.46}, { 32, 193.25 } },
        "IBM-9117-MMA", 4700.0, 5, {{ 2, 20.13}, { 4, 40.26}, {  8, 74.89}, { 12, 105.89}, { 16, 134.35 } },
        /* # POWER6+ */
        "IBM-9117-MMA", 4400.0, 5, {{ 2, 19.08}, { 4, 38.16}, {  8, 70.97}, { 12, 100.35}, { 16, 127.32 } },
        "IBM-9117-MMA", 5000.0, 5, {{ 2, 21.16}, { 4, 42.32}, {  8, 78.71}, { 12, 111.30}, { 16, 141.21 } },

        /* # 595 */
        "IBM-9119-FHA", 4200.0, 8, {{ 8, 75.58}, { 16, 142.90}, { 24, 204.70}, { 32, 266.51}, { 40, 320.05}, { 48, 373.60}, { 56, 426.74}, { 64, 479.89 } },
        "IBM-9119-FHA", 5000.0, 8, {{ 8, 87.10}, { 16, 164.67}, { 24, 235.90}, { 32, 307.12}, { 40, 368.82}, { 48, 430.53}, { 56, 491.77}, { 64, 553.01 } },

        /* # New faster CPUs for POWER6 */
        "IBM-8203-E4A", 4700.0, 2, {{ 2, 20.13}, {  4, 39.73 } },
        "IBM-8204-E8A", 5000.0, 4, {{ 2, 21.18}, {  4, 41.81}, {  6, 60.2}, { 8, 78.6 } },
        "IBM-8234-EMA", 3600.0, 3, {{ 4, 31.32}, {  8, 57.3 }, { 16, 100.3 } },
        "IBM-9119-FHA", 4200.0, 8, {{ 8, 72.58}, { 16, 142.9}, { 24, 204.7 }, { 32, 266.51}, { 40, 320.05}, { 48, 373.6 }, { 56, 426.74}, { 64, 479.89 } },
        "IBM-9119-FHA", 5000.0, 7, {{ 16, 164.67}, { 24, 235.9}, { 32, 307.12}, { 40, 368.82}, { 48, 430.53}, { 56, 491.77}, { 64, 553.01 } },

	/* POWER7 */
        /* POWER7 p260 */
        "IBM-7895-22X", 3300.0, 1, { {  8,  92.8 } },
        "IBM-7895-22X", 3220.0, 1, { { 16, 163.8 } },
        "IBM-7895-22X", 3550.0, 1, { { 16, 176.6 } },
        /* POWER7+ p260 */
        "IBM-7895-23A", 4000.0, 1, { {  4,  61.2 } },
        "IBM-7895-23X", 4000.0, 1, { {  8, 115.5 } },
        "IBM-7895-23X", 3600.0, 1, { { 16, 197.7 } },
        "IBM-7895-23X", 4100.0, 1, { { 16, 218.5 } },
        /* POWER7 p460 */
        "IBM-7895-42X", 3300.0, 1, { { 16, 174.0 } },
        "IBM-7895-42X", 3220.0, 1, { { 32, 307.0 } },
        "IBM-7895-42X", 3550.0, 1, { { 32, 331.1 } },
        /* POWER7+ p460 */
        "IBM-7895-43X", 4000.0, 1, { { 16, 225.0 } },
        "IBM-7895-43X", 3600.0, 1, { { 32, 372.6 } },
        "IBM-7895-43X", 4100.0, 1, { { 32, 411.7 } },

        /* POWER7 Power 750 from May 2010 */
        "IBM-8233-E8B", 3000.0, 4, { { 8,  81.24}, { 16, 155.99}, { 24, 224.23}, { 32, 292.47  } },
        "IBM-8233-E8B", 3300.0, 4, { { 8,  86.99}, { 16, 167.01}, { 24, 240.08}, { 32, 313.15  } },
        "IBM-8233-E8B", 3500.0, 1, { { 32, 331.06  } },
        /* POWER7 Power 750 April 2011 */
        "IBM-8233-E8B", 3200.0, 4, { { 8, 85.29}, { 16, 163.75}, { 24, 235.39}, { 32, 307.03  } },
        "IBM-8233-E8B", 3600.0, 4, { { 8, 93.05}, { 16, 178.65}, { 24, 256.81}, { 32, 334.97  } },
        "IBM-8233-E8B", 3700.0, 7, { { 4, 52.90}, { 6, 76.71}, { 8, 101.67}, { 12, 146.00}, { 16, 190.44}, { 18, 211.71}, { 24, 276.14  } },
        /* POWER7+ Power 750 Feb 2013 */
        "IBM-8408-E8D", 3500.0, 4, { { 8, 104.5}, { 16, 197.0}, { 24, 275.9}, { 32, 354.9  } },
        "IBM-8408-E8D", 4000.0, 4, { { 8, 117.1}, { 16, 220.7}, { 24, 309.2}, { 32, 397.7  } },
        /* POWER7+ Power 760 Feb 2013 */
        "IBM-9109-RMD", 3100.0, 4, { { 12, 142.1}, { 24, 264.8}, { 36, 370.7}, { 48, 476.7  } },
        "IBM-9109-RMD", 3400.0, 4, { { 12, 151.4}, { 24, 282.1}, { 36, 395.0}, { 48, 507.8  } },

        /* Power 755 assuming 750 rPerf numbers are OK */
        "IBM-8236-E8C", 3300.0, 4, { {  8, 86.99}, {  16, 167.01}, {24, 240.08}, { 32, 313.15  } },
        /* Power 755 June 2012 - no values present yet for 3.6 GHz version. */
        /* Made ESTIMATION based on number above 36/33 00.0, 2, 313.15 = 341.62 */
        "IBM-8236-E8C", 3600.0, 1, { {  32, 341.62  } },

        /* Power 770 */
        "IBM-9117-MMB", 3100.0, 4, { { 16, 165.30}, {32, 306.74}, {48, 443.06}, {64, 579.39 } },
        "IBM-9117-MMB", 3500.0, 4, { { 12, 140.75}, {24, 261.19}, {36, 377.26}, {48, 493.37 } },
        /* Power 770 C models - Nov 2011 */
        "IBM-9117-MMC", 3300.0, 4, { { 16, 173.1}, {32, 321.2}, {48, 464.0}, {64, 606.8 } },
        "IBM-9117-MMC", 3700.0, 4, { { 12, 147.5}, {24, 273.7}, {36, 395.4}, {48, 517.0 } },
        /* Power 770 D models - Oct 2012 */
        "IBM-9117-MMD", 3800.0, 4, { { 16, 219.3}, {32, 410.8}, {48, 570.1}, {64, 729.3 } },
        "IBM-9117-MMD", 4200.0, 4, { { 12, 184.2}, {24, 345.1}, {36, 478.9}, {48, 612.7 } },

        /* Power 780 */
        "IBM-9179-MHB", 3860.0, 4, { {16, 195.45}, { 32, 362.7}, {  48, 523.89}, { 64, 685.09  } },
        "IBM-9179-MHB", 4140.0, 4, { { 8, 115.16}, { 16, 226.97}, { 24, 326.24}, { 32, 425.5   } },
        "IBM-9179-MHB", 4150.0, 4, { { 8, 115.16}, { 16, 226.97}, { 24, 326.24}, { 32, 425.5   } },

        /* Power 780 C models - Nov 2011 */
        "IBM-9179-MHC", 3440.0, 4, { {24, 253.3}, { 48, 443.3}, { 72, 696.6}, { 96, 886.6 } },
        "IBM-9179-MHC", 3920.0, 4, { {16, 197.6}, { 32, 366.6}, { 48, 529.6}, { 64, 692.5 } },
        "IBM-9179-MHC", 4150.0, 4, { { 8, 115.9}, { 16, 227.0}, { 24, 326.2}, { 32, 425.5 } },
        "IBM-9179-MHC", 4140.0, 4, { { 8, 115.9}, { 16, 227.0}, { 24, 326.2}, { 32, 425.5 } },
        /* Power 780 D models - Oct 2012 - no more Turbo-Core */
        "IBM-9179-MHD", 3700.0, 4, { {32, 383.9}, { 64, 690.1}, { 96, 1151.6}, { 128, 1380.2 } },
        "IBM-9179-MHD", 4400.0, 4, { {16, 245.7}, { 32, 460.3}, { 48,  638.7}, {  64, 817.1 } },

        /* POWER7 Blades April 2010 */
        "IBM-8406-70Y", 3000.0, 1, { { 4, 45.13 } },
        "IBM-8406-71Y", 3000.0, 2, { { 8, 81.24}, { 16, 154.36 } },

        /* POWER7 Blades April 2010 */
        "IBM-7891-73X", 2400.0, 1, { { 16, 134.11 } },
        "IBM-7891-74X", 2400.0, 1, { { 32, 251.45 } },

        /* POWER7 Power 710 and 730 August 2010 */
        "IBM-8231-E2B", 3000.0, 2, { {  4, 45.13}, { 8, 86.66 } },
        "IBM-8231-E2B", 3700.0, 3, { {  6, 76.69}, { 8, 101.62}, { 12, 147.24 } },
        "IBM-8231-E2B", 3500.0, 2, { {  8, 91.96}, { 16, 176.57 } },
        /* POWER7 Power 710 and 730 C models  - Nov 2011 */
        "IBM-8231-E1C", 3000.0, 1, { {  4, 45.13 } },
        "IBM-8231-E1C", 3700.0, 1, { {  6, 76.69 } },
        "IBM-8231-E1C", 3500.0, 1, { {  8, 91.96 } },
        "IBM-8231-E2C", 3000.0, 2, { {  4, 45.13}, { 8, 86.66 } },
        "IBM-8231-E2C", 3700.0, 3, { {  6, 76.69}, { 8, 101.62}, { 12, 147.24 } },
        "IBM-8231-E2C", 3500.0, 2, { {  8, 91.96}, { 16, 176.57 } },
        /* POWER7+ Power 710 and 730 D models  - Feb 2013 */
        "IBM-8231-E1D", 3600.0, 1, { {  4, 53.9 } },
        "IBM-8231-E1D", 4200.0, 2, { {  6, 90.6}, { 8, 115.5 } },
        "IBM-8231-E2D", 4300.0, 1, { {  8, 120.4 } },
        "IBM-8231-E2D", 4200.0, 2, { {  12, 176.6}, { 16, 223.1 } },
        "IBM-8231-E2D", 3600.0, 1, { {  16, 197.8 } },

        /* POWER7 Power 720 and 740 August 2010 */
        "IBM-8202-E4B", 3000.0, 3, { {  4, 45.13}, { 6, 65.52}, { 8, 81.24 } },
        "IBM-8202-E4B", 3300.0, 2, { {  4, 48333}, { 8, 92.79 } },
        "IBM-8202-E4B", 3700.0, 3, { {  4, 52.93}, { 8, 101.62}, { 12, 147.24 } },
        "IBM-8202-E4B", 3500.0, 2, { {  8, 91.96}, { 16, 176.57 } },
        /* POWER7 Power 740 Express - October 2011 */
        "IBM-8205-E6B", 3300.0, 2, { {  4, 48.33}, { 8, 92.79 } },
        "IBM-8205-E6B", 3700.0, 4, { {  4, 52.93}, { 6, 76.69}, { 8, 101.62}, { 12, 147.24 } },
        "IBM-8205-E6B", 3500.0, 2, { {  8, 91.96}, { 16, 176.57 } },
        "IBM-8205-E6C", 3300.0, 2, { {  4, 48.33}, { 8, 92.79 } },
        "IBM-8205-E6C", 3700.0, 4, { {  4, 52.93}, { 6, 76.69}, { 8, 101.62}, { 12, 147.24 } },
        "IBM-8205-E6C", 3500.0, 2, { {  8, 91.96 }, {16, 176.57 } },
        /* Power 720 and 740 C models - same rPerf and B models - Nov 2011 */
        "IBM-8202-E4C", 3000.0, 3, { {  4, 45.13}, { 6, 65.52}, { 8, 81.24 } },
        "IBM-8202-E4C", 3300.0, 2, { {  4, 48.33}, { 8, 92.79 } },
        "IBM-8202-E4C", 3700.0, 4, { {  4, 52.93}, { 6, 76.69}, { 8, 101.62}, { 12, 147.24 } },
        "IBM-8202-E4C", 3550.0, 2, { {  8, 91.96}, { 16, 176.57 } },
        /* POWER7+ Power 720 and 740 D models - Feb 2013 */
        "IBM-8202-E4D", 3600.0, 2, { {  4, 53.9}, { 6, 79.5}, { 8, 102.4 } },
        "IBM-8205-E6D", 4200.0, 4, { {  6, 90.6}, { 8, 115.5}, { 12, 176.6}, { 18, 233.1 } },
        "IBM-8205-E6D", 3600.0, 2, { {  8, 102.4}, { 16, 197.7 } },

        /* POWER7 Power 795  August 2010 */
        "IBM-9119-FHB", 3700.0, 2, { {24, 273.51}, { 192, 2188.08 } },
        "IBM-9119-FHB", 4000.0, 2, { {32, 372.27}, { 256, 2978.16 } },
        "IBM-9119-FHB", 4200.0, 3, { {24, 347.36}, {  48,  694.71}, {  128, 1852.56 } },

	/* POWER8 */
        "IBM-8284-22A", 3900.0, 2, { {6,  120.8}, { 12, 235.6 }},
        "IBM-8284-22A", 3800.0, 2, { {6,  120.8}, { 12, 235.6 }},
        "IBM-8284-22A", 4100.0, 2, { {8,  155.1}, { 16, 302.4 }},
        "IBM-8284-22A", 3400.0, 2, { {10, 177.8}, { 20, 346.7 }},

        "IBM-8286-41A", 3000.0, 2,  { {4, 66.9}, { 6,  97.5 }},
        "IBM-8286-41A", 3700.0, 1,  { {8, 143.9 }},

        "IBM-8286-42A", 3900.0, 2,  { {6,  120.8}, { 12, 235.6 }},
        "IBM-8286-42A", 3800.0, 2,  { {6,  120.8}, { 12, 235.6 }},
        "IBM-8286-42A", 4100.0, 2,  { {8,  166.0}, { 16, 323.6 }},
        "IBM-8286-42A", 3500.0, 1,  { {24, 421.9           }},

        "IBM-8408-E8E", 3000.0, 2,  { {24, 383.0}, { 48, 746.9 }},
        "IBM-8408-E8E", 3300.0, 2,  { {20, 347.8}, { 40, 678.3 }},
        "IBM-8408-E8E", 3700.0, 2,  { {16, 304.5}, { 32, 593.8 }},

        "IBM-9119-MME", 4000.0, 2,  { {32, 674.5}, { 64, 1349.0 }},
        "IBM-9119-MME", 4100.0, 2,  { {40, 856.0}, { 80, 1711.9 }},

        "IBM-9119-MHE", 4000.0, 3,  { {48, 976.4}, { 96, 1952.9}, { 192, 3905.8 }},
        "IBM-9119-MHE", 4100.0, 3,  { {40, 856.0}, { 80, 1711.9}, { 160, 3424.0 }},
        "IBM-9119-MHE", 4300.0, 3,  { {32, 716.3}, { 64, 1432.5}, { 128, 2865.0 }},

        "IBM-8408-44E", 3600.0, 4,  { {12, 221.0}, { 24, 440.7}, { 36, 640.0}, { 48, 859.3 }},
        "IBM-8408-44E", 3900.0, 4,  { {10, 197.0}, { 20, 393.1}, { 30, 579.8}, { 40, 766.5 }},
        "IBM-8408-44E", 4200.0, 4,  { {8,  168.0}, { 16, 334.7}, { 24, 493.7}, { 32, 652.7 }},

        "IBM-9080-MME", 4000.0, 2,  { {32, 674.5}, { 64, 1349.0 }},

        "IBM-9080-MHE", 4000.0, 3,  { {48, 976.4}, { 96, 1952.9}, { 192, 3905.8 }},
        "IBM-9080-MHE", 4100.0, 3,  { {40, 856.0}, { 80, 1711.9}, { 160, 3424.0 }},
        "IBM-9080-MHE", 4300.0, 3,  { {32, 716.3}, { 64, 1432.5}, { 128, 2865.0 }},

	/* POWER9 */
	"IBM-9009-42A", 3300.0, 2, { {8, 219.4}, {16, 427.8}},
	"IBM-9009-42A", 2900.0, 2, {{10, 256.1}, {20, 499.5}},
	"IBM-9009-42A", 2700.0, 1, {{24, 583.1}},

	"IBM-9009-41A", 2300.0, 2, {{ 4, 76.1},  { 6, 111.5}},
	"IBM-9009-41A", 2800.0, 1, {{ 8, 172.0}},

	"IBM-9009-22A", 2300.0, 1, {{ 4, 89.8}},
	"IBM-9009-22A", 3000.0, 2, {{ 8, 202.3}, {16, 394.5}},
	"IBM-9009-22A", 2500.0, 2, {{10, 218.6}, {20, 426.4}},

	"IBM-9040-MR9", 2850.0, 2, {{ 24, 587.8}, {48, 1146.4 }},
	"IBM-9040-MR9", 2800.0, 2, {{ 22, 549.6}, {44, 1071.9 }},
	"IBM-9040-MR9", 3000.0, 2, {{ 20, 530.2}, {40, 1034.1 }},
	"IBM-9040-MR9", 3300.0, 2, {{ 16, 446.3}, {32,  870.4 }},

	/* POWER9 G models = same as A models */
	"IBM-9009-42G", 3300.0, 2, { {8, 219.4}, {16, 427.8}},
	"IBM-9009-42G", 2900.0, 2, {{10, 256.1}, {20, 499.5}},
	"IBM-9009-42G", 2700.0, 1, {{24, 583.1}},

	"IBM-9009-41G", 2300.0, 2, {{ 4, 76.1},  { 6, 111.5}},
	"IBM-9009-41G", 2800.0, 1, {{ 8, 172.0}},

	"IBM-9009-22G", 2300.0, 1, {{ 4, 89.8}},
	"IBM-9009-22G", 3000.0, 2, {{ 8, 202.3}, {16, 394.5}},
	"IBM-9009-22G", 2500.0, 2, {{10, 218.6}, {20, 426.4}},

	"IBM-9040-MR9", 2850.0, 2, {{ 24, 587.8}, {48, 1146.4 }},
	"IBM-9040-MR9", 2800.0, 2, {{ 22, 549.6}, {44, 1071.9 }},
	"IBM-9040-MR9", 3000.0, 2, {{ 20, 530.2}, {40, 1034.1 }},
	"IBM-9040-MR9", 3300.0, 2, {{ 16, 446.3}, {32,  870.4 }},

        "IBM-9080-M9S", 2900.0, 14, {{ 8, 228.8}, { 12, 334.0}, { 16, 457.3}, { 20, 554.3}, { 24, 651.3}, { 28, 760.7}, { 32, 870.1}, { 36, 960.6}, { 40, 1073.3}, {  44, 1171.7}, {  48, 1270.2}, {  96, 2540.4}, { 144, 3810.6}, { 192, 5081.7 }},
        "IBM-9080-M9S", 3000.0, 13, {{ 8, 230.6}, { 12, 336.7}, { 16, 461.0}, { 20, 558.8}, { 24, 656.6}, { 28, 766.9}, { 32, 877.2}, { 36, 968.4}, { 40, 1082.0}, {  44, 1181.4}, {  88, 2362.9}, { 132, 3544.3}, { 176, 4725.8 }},
        "IBM-9080-M9S", 3100.0, 12, {{ 8, 234.0}, { 12, 341.6}, { 16, 467.7}, { 20, 566.9}, { 24, 666.1}, { 28, 778.0}, { 32, 889.8}, { 36, 982.4}, { 40, 1098.1}, {  80, 2196.2}, { 120, 3294.3}, { 160, 4392.4 }},
        "IBM-9080-M9S", 3400.0, 10, {{ 8, 239.1}, { 12, 349.1}, { 16, 477.9}, { 20, 579.3}, { 24, 680.7}, { 28, 795.0}, { 32, 910.0}, { 64, 1820.0}, { 96, 2729.9}, { 128, 3639.9 }},
};

int records = sizeof(rperf_data) / sizeof(struct rperf_struct);

void rperf_lookup()
{
int i;
int j;
double ret;
double mhz;
double cpu_vp;
double cpu_entitled;
double cpu_consumed;

    mhz = config.processorMHz;
    cpu_vp = config.vcpus.online;

    cpu_entitled = cpu_util.entitlement;
    cpu_consumed = cpu_util.physical_consumed;

    psection("rperf");
    pstring("mtm",saved_machine_type);
    pdouble("nominal_mhz",mhz);
    pdouble("cpu_vp",cpu_vp);
    pdouble("cpu_entitled",cpu_entitled);
    pdouble("cpu_consumed",cpu_consumed);

    for(i=0;i<records;i++) {
	if( !strncmp(saved_machine_type, rperf_data[i].mtm,12) ) {
	    if( mhz >= (rperf_data[i].mhz * 0.9) && mhz <= (rperf_data[i].mhz * 1.10) ) {  /* within 10% */
		for(j=0;j<rperf_data[i].stats;i++){

                    if(cpu_vp <= rperf_data[i].match[j].cpus) {
			pdouble("official_rperf",rperf_data[i].match[j].rperf);
			pdouble("official_cpus",rperf_data[i].match[j].cpus);
			if( cpu_vp != 0.0) pdouble("rperf_vp",rperf_data[i].match[j].rperf/ rperf_data[i].match[j].cpus * cpu_vp);
			if( cpu_entitled != 0.0) pdouble("rperf_entitlement",rperf_data[i].match[j].rperf/ rperf_data[i].match[j].cpus * cpu_entitled);
			if( cpu_consumed != 0.0) pdouble("rperf_consumed",rperf_data[i].match[j].rperf/ rperf_data[i].match[j].cpus * cpu_consumed);
			psectionend();
			return;
	    	    }
	        }
	    }
	} 
	/* else printf("ignore %s\n",rperf_data[i].mtm); */
    }
    psectionend();
}

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
#ifdef EXTRA

#include "extra.c"

#endif /* EXTRA */

void rmspace(char *s)
{
int i;
        for(i=0;i<=strlen(s);i++) {
            s[i] = s[i+1];
        }


}
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
/* MAIN */
int    main(int argc, char **argv)
{
    char   buffer[256];
    int    commlen;
    int    i;
    int    j;
    int    found;
    int    processes = 0;
    long   maxloops = -1;
    long   seconds = 60;
    int    vios_mode = 0;
    int    directory_set = 0;
    char   directory[4096+1];
    char   filename[64];
    char  *s;
    int    target_hostmode = 0;
    int    kill_on = 0;
    int    no_pid = 0;
    int       ch;
    double    elapsed;
    double    previous_time;
    double    current_time;

    double    sleep_start;
    double    sleep_end;
    double    sleep_time = 0.0;
    double    execute_start;
    double    execute_end;
    double    execute_time = 0.0;
    double    sleep_overrun = 0.0;
    double    sleep_target;
    long sleep_secs;
    long sleep_usecs;

    struct timeval tv;
    FILE   * fp;
    int    child_pid = 0;
    int    processor_pool = 0;
    int    pause = 0;
    int    pause_seconds = 0;
    char *cmd;
    char *njmon_name;

    debug = atoi(getenv("NJMON_DEBUG"));
    FUNCTION_START;
    njmon_internal_stats = atoi(getenv("NJMON_STATS"));

    /* find command name without the directory part */
    for(i=strlen(argv[0]); i > 0; i--){
                if(argv[0][i] == '/') {
                        cmd = &argv[0][i+1];
                        break;
                }
    }
    if(i==0) /* if no slash that use the whole command name */
        cmd = argv[0];
    /* check command name starts nimon or njmon and set mode appropriately */
    if(!strncmp(cmd, "njmon",5)) {
	mode = NJMON;
	njmon_name = "njmon";
    }
    else if (!strncmp(cmd, "nimon",5)) {
	mode = NIMON;
	njmon_name = "nimon";
    }
    else {
        printf("Invalid command name: must start with njmon or nimon and not \"%s\"\n", cmd);
	exit(76);
    }

    found = 0;
    for(i=1;i<argc;i++) {
	if(!strncmp("-I",argv[i],2)) {
	    mode = NIMON;
	    found++;
	    break;
	}
	if(!strncmp("-J",argv[i],2)) {
	    mode = NJMON;
	    found++;
	    break;
	}
    }
    if(found > 1)
        printf("Invalid options: both -I and -J is not valid\n");

    signal(SIGUSR1, interrupt);
    signal(SIGUSR2, interrupt);

    /* command line processing */
    int  option_a = 0;;
    int  argumentc;
    char **argumentv;
    FILE *cmd_fp;
    char *cmd_parts[64];
    char cmd_buffer[1024+1];
    int reduced_stats = 0;
    int proc_pid_on = 1;
    int filesystems_on = 1;
    int more;
    int c_option=0;
    int s_option=0;

    argumentc = argc;
    argumentv = argv;
    char *cli_options;

    commlen = 1;  /* for the terminating zero */
    for (i = 0; i < argc; i++) {
        commlen = commlen + strlen(argv[i]) + 1; /* +1 for spaces */
    }
    njmon_command = malloc(commlen);
    DEBUG printf("commlen=%d\n",commlen);
    njmon_command[0] = 0;
    for (i = 0; i < argc; i++) {
        strcat(njmon_command, argv[i]);
        if ( i != (argc - 1) )
            strcat(njmon_command, " ");
    }
    DEBUG printf("njmon_command=\"%s\"\n",njmon_command);

    if(mode == NJMON) 
	cli_options = "a:bc:CdDefFhi:IJkK:Lm:nop:PrRs:t:uUvVX:W?@";
    if(mode == NIMON) 
	cli_options = "a:bc:CdDfFhHi:IJkK:Lm:nop:PrRs:t:uUvVwWx:X:y:z:?@";

    while (-1 != (ch = getopt(argumentc, argumentv, cli_options)))
        {
            switch (ch) {
	    case ' ':
		DEBUG printf("getopt(space)\n");
		break;
            case '@':
                printf("Version %s Mode: %s\n", njmon_version, njmon_name);
                exit(0);
	    case 'a':
		if(option_a++) break; /* only allow -a option once */
                cmd_fp = fopen(optarg,"r");
                if(cmd_fp == NULL) {
                    printf("%s stopping: -a cmdfile - opening %s failed errno=%d\n",argv[0],optarg,errno);
                    exit(2345);
                }
                cmd_parts[0] = argv[0];
                if(fgets(cmd_buffer, 1024, cmd_fp) == NULL) {
                    printf("%s stopping: -a cmdfile - read %s failed errno=%d\n",argv[0],optarg,errno);
                    exit(7568);
                }
                cmd_buffer[1024] = 0; /* force NULL */
                if (cmd_buffer[strlen(cmd_buffer)-1] == '\n')
                    cmd_buffer[strlen(cmd_buffer)-1] = 0;   /* remove trailing newline */
                /* remove doube spaces */
                for(i=0;i<strlen(cmd_buffer);i++) {
                    if( (cmd_buffer[i] == ' ') && (cmd_buffer[i+1] == ' ') ) {
                        rmspace(&cmd_buffer[i]);
                        i--;
                    }
                }

                DEBUG printf("undouble spaces=\"%s\"\n",cmd_buffer);
                /* remove start space */
                if(cmd_buffer[0] == ' ')
                        rmspace(cmd_buffer);
                /* remove end space */
                if(cmd_buffer[strlen(cmd_buffer) -1] == ' ')
                        cmd_buffer[strlen(cmd_buffer) -1] = 0;
                DEBUG printf("un start end spaces=\"%s\"\n",cmd_buffer);
		njmon_command = realloc((void *)njmon_command, strlen(njmon_command) + strlen(cmd_buffer) +4);
                sprintf(&njmon_command[strlen(njmon_command)], " %s", cmd_buffer);
                DEBUG printf("njmon_command-a=\"%s\"\n",njmon_command);

                j=1; /* skip 0th entry = command name */
                cmd_parts[0] = argv[0];;
                cmd_parts[1] = cmd_buffer;
                for(i=0,more=1;(i<1024) && more;i++) {
		    if(cmd_buffer[i] == 0) 
			more=0;
                        if(cmd_buffer[i] == ' ' || cmd_buffer[i] == 0) {
                            cmd_buffer[i] = 0;
                            j++;
                            cmd_parts[j] = &cmd_buffer[i+1];
                        }
                   if(j >= 64 ) break; /* hacking attempt */
                }
                optind = 0;     /* rewind to the start of new parameters */
                argumentc = j;
                argumentv = cmd_parts;
		/*
                 *   printf("reprogrammed %d arguments\n",j);
                 *   for(i=0;i<j;i++)
                 *       printf("argumentv[%d]=%s\n",i,argumentv[i]);
		 */
		fclose(cmd_fp);
                break;
            case 'b':
		DEBUG printf("option -b: no processes pid\n");
                proc_pid_on = 0;
                break;
            case 'F':
		DEBUG printf("option -F: no filesystems\n");
                filesystems_on = 0;
                break;
            case 's':
		DEBUG printf("option -s: seconds=\"%s\"\n",optarg);
		if(s_option != 0) {
		    printf("njmon: more than one -s option encountered\n");
		    exit(44);
		}
		s_option++;
                if (isdigit(optarg[0])) {
                    seconds = atoi(optarg);
                    if (seconds < 1)
                        seconds = 1;
                } else {
                    printf("njmon: -s option required a number\n");
                    exit(100);
                }
                break;
            case 'c':
		DEBUG printf("option -c: count=\"%s\"\n",optarg);
		if(c_option != 0) {
		    printf("njmon: more than one -c option encountered\n");
		    exit(44);
		}
		c_option++;
                if (isdigit(optarg[0])) {
                    maxloops = atoi(optarg);
                    if (maxloops < 1)
                        maxloops = 1;
                } else {
                    printf("njmon: -c option required a number\n");
                    exit(101);
                }
                break;
            case '?':
            case 'h':
                hint();
                exit(0);
            case 'H':
		if(mode == NIMON) {
                    fullhostname_tag = 1;
		} else {
		    printf("Invalid in nimon mode option -H: fule hostname on\n");
		    exit(59);
		}
                break;
            case 'd':
                debug = 1;
		DEBUG printf("option -d: debug on\n");
                break;
            case 'D':
		DEBUG printf("option -D: skip dangerous stats\n");
                danger = 1;
                break;
            case 'f':
		DEBUG printf("option -f: file output\n");
                file_output++;
		DEBUG printf("file_output=%d\n", file_output);
                break;
            case 'm':
		DEBUG printf("option -m: directory=\"%s\"\n",optarg);
                directory_set = 1;
                strncpy(directory, optarg, 4096);
                directory[4096] = 0;
                break;
            case 'P':
		DEBUG printf("option -P: processes on\n");
                processes = 1;
                break;
            case 'R':
		DEBUG printf("option -R: reduce stats\n");
                reduced_stats = 1;
                break;
/* depricated
            case 'r':
                rpm_stuck = 1;
                break;
*/
            case 'I':
		DEBUG printf("option -I: InfluxDB nimon mode\n");
                mode = NIMON;
                break;
            case 'J':
		DEBUG printf("option -J: JSON njmon stats\n");
                mode = NJMON;
                break;
 	    case 'K': /* user specified pid file */
 		DEBUG printf("option -K: PIDfile\n");
 		pid_filename = (char *)malloc(strlen(optarg) +1);
 		strcpy(pid_filename, optarg);
 		kill_on = 1;
 		break;
            case 'k':
		DEBUG printf("option -k: kill mode on\n");
                kill_on = 1;
                break;
            case 'L':
		DEBUG printf("option -L: LV stats off\n");
                lvs = 0;
                break;
            case 'V':
		DEBUG printf("option -V: VG stats off\n");
                vgs = 0;
                break;
            case 'v':
		DEBUG printf("option -v: VIOS mode on\n");
                vios_mode = 1;
                break;
#ifdef SSP
            case 'u':
		DEBUG printf("option -u: SSP on\n");
                ssp_mode = 1;
                break;
            case 'U':
		DEBUG printf("option -U: SSP nodes on\n");
                ssp_mode = 1;
                ssp_node_mode = 1;
                break;
#else
            case 'u':
		DEBUG printf("option -u: SSP on ignored\n");
                break;
            case 'U':
		DEBUG printf("option -U: SSP nodes on ignored\n");
                break;
#endif /* SSP */
            case 'W':
		DEBUG printf("option -W: Warnings off\n");
                warnings = 0;
                break;
            case 'i':
		DEBUG printf("option -i: hostname or IP address=\"%s\"\n",optarg);
                strncpy(target_host, optarg, 1024);
                target_host[1024] = 0;
                target_hostmode = 1;

		if(mode == NIMON){
		    if (target_port == 0)
		        target_port = 8086;
		}
                break;
            case 'p':
		DEBUG printf("option -p: port=\"%s\"\n",optarg);
                if (isdigit(optarg[0])) {
                    target_port = atoi(optarg);
                } else {
                    printf("njmon: -p option required a number\n");
                    exit(101);
                }
                break;
            case 'w':
		if(mode == NIMON) {
		    DEBUG printf("option -w: telegraf mode\n");
                    telegraf_mode = 1;
		} else {
		    printf("Invalid njmon mode option -w: telegraf mode\n",optarg);
		    exit(61);
		}
                break;
            case 'x':
		if(mode == NIMON) {
		DEBUG printf("option -x database name=\"%s\"\n",optarg);
                strncpy(influx_database, optarg, 63);
		} else {
		    printf("Invalid njmon mode option -x: database name=\"%s\"\n",optarg);
		    exit(62);
		}
                break;
            case 'y':
		if(mode == NIMON) {
		DEBUG printf("option -y: user=\"%s\"\n",optarg);
                strncpy(influx_username, optarg, 63);
		} else {
		    printf("Invalid njmon mode option -y: user=\"%s\"\n",optarg);
		    exit(63);
		}
                break;
            case 'z':
		if(mode == NIMON) {
		DEBUG printf("option -z: passwd=\"%s\"\n",optarg);
                strncpy(influx_password, optarg, 63);
		} else {
		    printf("Invalid njmon mode option -z: passwd=\"%s\"\n",optarg);
		    exit(64);
		}
                break;
            case 't':
		DEBUG printf("option -t: threashold=\"%s\"\n",optarg);
                if( atof(optarg) >= 0)
			cpu_threshold = atof(optarg);
                break;
            case 'C':
		DEBUG printf("option -C: processor pool\n");
                processor_pool = 1;
                break;
            case 'e':
		if(mode == NJMON) {
		    DEBUG printf("option -e: elastic JSON style\n");
                    elastic = 1;
		} else {
		    printf("Invalid nimon mode option -e: elastic JSON style\n");
		    exit(65);
		}
                break;
            case 'o':
		DEBUG printf("option -o: Oracle disk workaround\n");
                oracle = 1;
                break;
            case 'r':
		DEBUG printf("option -r: random start pause\n");
                pause = 1;
                break;
            case 'n':
		DEBUG printf("option -n: don't output the PID\n");
                no_pid = 1;
                break;
            default:
                printf("%s stopping: Unexpected command parameter \"%c\" = 0x%x\n - bailing out\n", argv[0],(char)ch, ch);
                exit(12);
                break;
            }
        }
    if (target_hostmode == 1 && target_port == 0) {
        printf("%s -i %s set but not the -p port option\n", argv[0], target_host);
        exit(52);
    }
    if (target_hostmode == 0 && target_port != 0) {
        printf("%s -p %d but not the -i hostname or ip-address option\n", argv[0], target_port);
        exit(53);
    }
    if (target_hostmode == 1) { /* We are attempting sending the data remotely */
        if (isalpha(target_host[0])) {
            struct hostent *he;

            he = gethostbyname(target_host);
            if ( he == NULL) {
                printf("target_hostname=%s to IP address convertion failed, bailing out\n", target_host);
                exit(98);
            }
            /*
                printf("name=%s\n",he->h_name);
                printf("type=%d = ",he->h_addrtype);
                switch(he->h_addrtype) {
                case AF_INET: printf("IPv4\n"); break;
                case AF_INET6: printf("(IPv6\n"); break;
                default: printf("unknown\n");
                }
                printf("length=%d\n",he->h_length);
            */

            /* this could return multiple IP addresses but we assume its the first one */
            if ( he->h_addr_list[0] != NULL) {
                strcpy( target_ip, inet_ntoa( *(struct in_addr *)(he->h_addr_list[0])));
            } else {
                printf("target_host=%s to IP address convertion failed, bailing out\n", target_host);
                exit(98);
            }
        } else {
	    strcpy( target_ip, target_host);
	}
    }
    get_hostname();
    get_time();
    if (directory_set) {
        if (chdir(directory) == -1) {
            perror("Change Directory failed");
            printf("Directory attempted was: %s\n", directory);
            exit(11);
        }
    }
    DEBUG printf("forking debug=%d\n", debug);
    if (debug == 0) { /* if not debuging mode */
        if ((child_pid = fork()) != 0) {
            DEBUG printf("forked parent child_pid=%d\n", child_pid);
            if(!no_pid)
		printf("%d\n", child_pid);
            exit(0); /* parent returns OK */
        }
    }
    if (file_output) {
        get_hostname();
        get_time();
        get_localtime();

	if(mode == NJMON) {
	    if(file_output >= 2) {
                sprintf( filename_ff2, "%s_%02d%02d%02d_%02d%02d",
                    hostname, tim->tm_year, tim->tm_mon, tim->tm_mday, tim->tm_hour, tim->tm_min, 1); /* 1 = first loop */
	    } else {
                sprintf( filename, "%s_%02d%02d%02d_%02d%02d.json",
                    hostname, tim->tm_year, tim->tm_mon, tim->tm_mday, tim->tm_hour, tim->tm_min);
                if ((fp = freopen(filename, "w", stdout)) == 0 ) {
                    nwarning2("opening file for stdout filename=%s\n", filename);
                    exit(12);
                }
	    }
	} else {
            sprintf( filename, "%s_%02d%02d%02d_%02d%02d.influxlp",
                hostname, tim->tm_year, tim->tm_mon, tim->tm_mday, tim->tm_hour, tim->tm_min);
            if ((fp = freopen(filename, "w", stdout)) == 0 ) {
                nwarning2("opening file for stdout filename=%s\n", filename);
                exit(13);
            }
	}
        sprintf( filename, "%s_%02d%02d%02d_%02d%02d.err",
            hostname, tim->tm_year, tim->tm_mon, tim->tm_mday, tim->tm_hour, tim->tm_min);
        if ((fp = freopen(filename, "w", stderr)) == 0 ) {
            nwarning2("ERROR opening file for stder filename=%s\n", filename);
            exit(14);
        }
    }
    fflush(NULL);
#ifdef ASSERT_TEST
    ASSERT(2 == 1, "assert test", DUMP, (long long)debug);
#endif
    /* disconnect from terminal */
    DEBUG printf("child running\n");
    if (!debug ) {
        /*
	close(0);
        close(1);
        close(2);
	*/
        setpgrp(); /* become process group leader */
        signal(SIGHUP, SIG_IGN); /* ignore hangups */
    }
#define RANGE(min,max) ((long)random() % ((max) - (min) +1)) + (min)
    if (pause) {
        long    pause_seconds;
        pause = seconds;
        /* sanity checks */
        if (pause > 300) 
            pause = 300; /* don't delay the first snapshot too much */
        if (pause < 2) 
            pause = 5;
        /* seed the random generator with a different value on every end point using PID */
        srandom(getpid());
        pause_seconds = RANGE(0, pause);
        DEBUG printf("pause=%d\n", pause_seconds);
        sleep(pause_seconds);
    }

    output_size = INITIAL_BUFFER_SIZE;
    output = malloc(output_size);
    if (kill_on) {
        check_pid_file();
        make_pid_file();
    }
    /* seed incrementing counters */
    logged_errors();
    aix_server_init();
    ps_part_total_init(); 
    ps_cpu_init();
    ps_cpu_total_init();
    ps_memory_init();
    ps_memory_page_init();
    ps_paging_init();
    ps_vminfo_init();
    ps_net_interface_init();
    ps_net_adapter_init();
    ps_net_total_init();
    if (vios_mode)
        ps_net_bridge_init();
    if(!reduced_stats) 
	ps_netbuffs_init();
    ps_disk_init();
    ps_disk_total_init();
    ps_disk_adapter_init();
#ifdef VIOS
    if (vios_mode) {
        ps_vios_vhost_init();
        ps_vios_target_init();
        ps_vios_vfc_init();
    }
#endif /* VIOS */
#ifdef SSP
    if (ssp_mode) {
        ps_ssp_init();
        ps_ssp_node_init();
    }
#endif /* SSP */
    ps_fc_stat_init();
    ps_nfs_init();
    ps_lv_init();
    ps_vg_init();
    ps_tape_init();
    dr_lpar_init();
#ifndef NOGPFS
    gpfs_init();
#endif /* NOGPFS */

    if (processes) 
        ps_process_init();

#ifdef EXTRA
    extra_init();
#endif /* EXTRA */

    gettimeofday(&tv, 0);
    previous_time = (double)tv.tv_sec + (double)tv.tv_usec * 1.0e-6;

    /* if a long time between snapshot then do a quick one now so we have one stats set in the bank */
    DEBUG printf("sleep(%d)\n",seconds);
    if (seconds <= 60)
        sleep(seconds);
    else
        sleep(60);

    gettimeofday(&tv, 0);
    current_time = (double)tv.tv_sec + (double)tv.tv_usec * 1.0e-6;
    elapsed = current_time - previous_time;

    if(mode == NIMON)
        ps_part_config_init(); /* only saved the architecture */

    /* pre-amble */
    for (loop = 0; maxloops == -1 || loop < maxloops; loop++) {
	/* sanity check */
	if(execute_time < 0.0)
	    execute_time = 0.0;
	if(sleep_overrun < 0.0) /* seen this at a 1/1000th of a second scale due to sleep() inaccurate on some HW */
            sleep_overrun = 0.0;

        sleep_target = (double)seconds - sleep_overrun - execute_time;
	/* sanity check */
        if(sleep_target > 0.0 && sleep_target <= (double)seconds) {
	    sleep_secs = (long)sleep_target;		/* whole seconds */
	    sleep_usecs= (sleep_target - (double)sleep_secs) * 1000000;	/* final fraction of a second in microseconds */
	} else {
	    /* execute or sleep time negative or very large (can't get enough CPU time) than the maths does not work */
	    sleep_secs = seconds;
	    sleep_usecs= 0;
	}

        if (loop != 0) {  /* don't calulate this on the first loop */
            DEBUG printf("calling usleep(%6.4f) . . .\n", sleep_target);
	    /* testing 
	    if(debug) {
		psection("sleeptime");
		plong("seconds", seconds);
		pdouble("sleep_target", sleep_target);
		plong("sleep_secs", sleep_secs);
		plong("sleep_usecs", sleep_usecs);
		pdouble("execute_time", execute_time);
		pdouble("sleep_overrun", sleep_overrun);
		psectionend();
	    }
	    */

            gettimeofday(&tv, 0);
            sleep_start = (double)tv.tv_sec + ((double)tv.tv_usec * 1.0e-6);

            if(sleep_secs > 0 && sleep_secs < (seconds + 1) )
	 	sleep (sleep_secs);  /* WHOLE SECOND SLEEP */
            if(sleep_usecs > 0.0 && sleep_usecs < 1000001 )
	 	usleep(sleep_usecs); /* MICRO SECOND SLEEP */

            gettimeofday(&tv, 0);
            sleep_end = (double)tv.tv_sec + ((double)tv.tv_usec * 1.0e-6);

            sleep_time = sleep_end - sleep_start;
            sleep_overrun = sleep_time - sleep_target;
        }
        gettimeofday(&tv, 0);
        execute_start = (double)tv.tv_sec + ((double)tv.tv_usec * 1.0e-6);

        psample();
        identity();

        /* calculate elapsed time to include sleep and data collection time */
        if (loop != 0)
            previous_time = current_time;
        gettimeofday(&tv, 0);
        current_time = (double)tv.tv_sec + ((double)tv.tv_usec * 1.0e-6);
        ASSERT(current_time != previous_time, "Elapsed Calculation", DUMP, (long long)elapsed);
        elapsed = current_time - previous_time;
        DEBUG pdouble("elapsed", elapsed);

        date_time(seconds, loop, maxloops, sleep_target, sleep_overrun, execute_time, elapsed);
        aix_server();
        ps_part_config();
        ps_part_total(elapsed); /* get hw ticks  = used in ps_cpu_???() */
        if (processor_pool)
            ps_processor_pool();             /* must follow ps_part_total() */
        ps_cpu_stats(elapsed,reduced_stats); /* must follow ps_part_total() */
        ps_cpu_total_stats(elapsed);	     /* must follow ps_part_total() */
        uptime();
        ps_memory(elapsed);
        ps_memory_page(elapsed);
        ps_paging();
        ASSERT(elapsed != 0.0, "main(looping) elapsed", DUMP, (long long)elapsed);
        ps_vminfo(elapsed);
        ps_net_interface_stats(elapsed);
        ps_net_adapter_stats(elapsed);
        ps_net_total_stats(elapsed);
        if (vios_mode)
            ps_net_bridge_stats(elapsed);
        if(!reduced_stats) 
            ps_netbuffs();
        ps_disk_stats(elapsed);
        ps_disk_total_stats(elapsed);
        ps_disk_adapter_stats(elapsed);
#ifdef VIOS
        if (vios_mode) {
            ps_vios_vhost_stats(elapsed);
            ps_vios_target_stats(elapsed);
            ps_vios_vfc_stats(elapsed);
        }
#endif /* VIOS */
#ifdef SSP
        if (ssp_mode) {
            ps_ssp();
            ps_ssp_node();
        }
#endif /* SSP */
        ps_fc_stats(elapsed);
        if(filesystems_on)
	    filesystems();
        ps_nfs(elapsed);
        ps_lv_stats(elapsed);
        ps_vg_stats(elapsed);
        ps_tape(elapsed);
        dr_lpar_stats();
#ifndef NOGPFS
        gpfs_data(elapsed);
#endif /* NOGPFS */

        if (processes) 
            ps_process_util(proc_pid_on);
	rperf_lookup();

#ifdef EXTRA
	extra_data(elapsed);
#endif /* EXTRA */

        psampleend(loop == (maxloops - 1));
        push();
        /* debugging = uncomment to crash here!
        ASSERT(loop == 42, "CRASHer", DUMP, loop); 
        */
	
	ps_disk_flush_minmax();

        gettimeofday(&tv, 0);
        execute_end = (double)tv.tv_sec + ((double)tv.tv_usec * 1.0e-6);
        execute_time = execute_end - execute_start;
    }
    /* finished main loop - clean up and exit */
    remove_ending_comma_if_any();
    if (njmon_internal_stats)
        pstats();
    push();
    close(sockfd); /* if a socket help it close cleanly */
    remove_pid_file();
    sleep(1);
    return 0;
}
/* - - - The End - - - */
