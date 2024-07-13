- [ ] Passive Mode



- [ ] Make a scenario for the installation( may a diagram)
	- [x] allow list of ips to ignore
		 - [ ] how to do this in ip table, (kind of exception)
- [ ] How to run the python program as a service in linux
	should be able to start, at boot time
	[ref] https://medium.com/codex/setup-a-python-script-as-a-service-through-systemctl-systemd-f0cc55a42267
	[ref] https://stackoverflow.com/questions/1603109/how-to-make-a-python-script-run-like-a-service-or-daemon-in-linux

- [x] open a TCP port and look watch for a connections (can use twisted framework)
- [ ] Add a port to the ip table, reject chain
	- [ ] log the rejections
		[ref] https://askubuntu.com/questions/348439/where-can-i-find-the-iptables-log-file-and-how-can-i-change-its-location
- [ ] python program should be able to read/parse the ip table logs,
	- [ ] may be logs specific to this HoneyPort
	- [ ] fancy red texts in the terminal or write the alerts into the prpper syslog format

	- [ ] how to write syslog events, using python
	[ref] https://signoz.io/blog/python-syslog/#:~:text=Syslog%20is%20an%20important%20messaging,audit%20and%20debug%20your%20software.
	[ref] https://www.syslog-ng.com/community/b/blog/posts/parsing-log-messages-with-the-syslog-ng-python-parser#:~:text=python%20%7B%20%22%22%22%20Regex%20parser,compile(pattern)%20self.
	[ref] https://www.loggly.com/use-cases/python-syslog-how-to-set-up-and-troubleshoot/


	- [ ] python script to send the syslog message or any other mesage to some remote syslog server.

- [ ] passive module
	- [ ] can be run host based scan dection modules
	- [ ] we might need to create rules for detections, 
			- [ ] http user agents
			- [ ] syn scans