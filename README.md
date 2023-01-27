# paraforce
A password based ssh brute force tool

## Getting Started
Paraforce is a multi-threaded tool written in Python that strives to be a highly configurable and reliable login brute-forcer

Currently It supports only the ssh service with the password or keyboard-interactive type.  Key based login was not in my intentions so it is left out for now

Since it is highly configurable it can be tailored on your environment. It offers:
- Multiple timers to configure in many stages of the connection
- A mechanism to select a random value from a range and use it as a delay in Retries, this will help to avoid detection from anti-brute forcing rules
- Delays on initial attemtps
- Multithread mode, to test in parallel many hosts
- Concurrent mode, to test in parallel many hosts and many credentials per host

### Requirements
Python >= 3.6 is required to run and the following dependencies
```
Linux (Sorry windows fans... it is not tested there)
pip install paramiko # Tested with Version: 2.12.0
```

## How to Use it

Check the help menu for options
```
python3 paraforce.py -h
```

By default it is running in multithread mode with 16 threads that each thread is working on a specific host/ip. Also, the port is set to 22 and the log level is set to ERROR.
An experimental mode of enabling concurrent ssh connections (-t 5 for 5 connections ) also exists but use it carefully.

### Usage Examples
It accepts files with ips and credentias in the following format :
my_hosts.txt
```
192.168.1.1
192.168.1.2
192.168.1.3
...
```
my_wordlist.txt
```
:admin:admin
:root:root
...
```
To execute it with default settings run it like this:
```
python3 paraforce.py -C my_wordlist.txt -H my_hosts.txt -M ssh
```
For specific host and credentials use this:
```
python3 paraforce.py --host 192.168.1.1 -U admin -P password -M ssh
```
The above executions will display all the succesful attempts and will create a log file "paraforce.log" which contains all the logs. You can change the successful output to be written in a file (--succ_out filename) or the filename of the complete log (-o err.log)

Example of setting max threads to 500 , port to 222 and loglevel to INFO
```
python3 paraforce.py -C my_wordlist.txt -H my_hosts.txt --port 222 -T 500 --loglevel INFO -M ssh
```
Example of configuring timers:
```
python3 paraforce.py -C my_wordlist.txt -H my_hosts.txt --socket_timeout 30 --auth_timeout 70 --banner_timeout 200 --attempt_delay 2 -M ssh
```

A helpful option for debugging is to run paraforce in single mode (only one thread is running) and use the --debug option:
```
python3 paraforce.py -C my_wordlist.txt -H my_hosts.txt --single --debug -M ssh
python3 paraforce.py --host 192.168.1.1 -U admin -P admin --single --debug -M ssh
```

## Timer configuration Guidelines

Initially you will need to run with the INFO loglevel so you can see all the logging and detect possible issues. **Before you proceed with any change verify that the host is not dead or is not malfunctioning.** You can do this simply by using ssh at the host like this:

```
ssh username@myhost -vvv # extra verbose is always helpful
```

So, the guidelines:

- If you have multiple "No existing session" or "timed out" or "Connection reset by peer" errors an increase in the socket timer might help. For example, increase it from the default 15 sec to 30 --socket_timeout 30

- If you have multiple "Error reading SSH protocol banner" errors then increasing the banner timeout (eg. --banner_timeout 200) might help the situation, also consider increasing the num of retries ( --req_retries) and the timer range between retries (eg. --retry_min_timer 3 --retry_max_timer 10). Multiple failures of this type are expected since the host might have anti-brute forcing rules or it might be even overloaded.

- If you have "Too many open files" then you need to raise the limit of your file descriptors. You can do that temporarily and increase them to 5000 like this : ulimit -n 5000


## Performance

In case you want to improve the performance you can play around with the timers, the number and the delay range of the retries. Most likely you will want to reduce them but be careful to check  the logs for any increase on errors.

An other option to investigate is to increase the threads so more hosts are being tested and even use the concurrent connections option.

An example on all above:
```
python3 paraforce.py -C my_wordlist.txt -H my_hosts.txt --socket_timeout 20 --auth_timeout 20 --banner_timeout 30 -T 200 -t 5 -M ssh
```

**para_report.sh** is a tool that parses the logs and provides the count of errors grouped. It can help you when you are trying to configure the values of your timers and attempts.
Combining the guidelines above and the association of the timers with the errors you can succeed the best performance on your brute force system.

Sample output of para_report.sh
```
2022-11-26 13:00:39,785 INFO Success Req: 20
2022-11-26 13:00:39,785 INFO Total Requests: 116

--------------------

2022-11-26 13:00:39,785 INFO Total time: 30.1984598636627
--------------------

socket timer related
--------------------
No existing session: 5
Timeouts: 50
Conn Resets: 10

Sum of all above: 65
--------------------

banner timer related
--------------------
Banner Error: 10
Retries: 20
--------------------

Informational
--------------------
AUTH Exception: 1
```

Using different configurations might produce better or worse results but you can compare it based on this report.
