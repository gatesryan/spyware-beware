# spyware-beware
CS 460 Final Project

This program is meant to be used to help detect unwanted network traffic on a system. It can be used to monitor a single port on a system or monitor all the ports on the entire system. When monitoring all of the ports on the system the program builds of baseline of what network traffic is normal, so that then it can compare the normal network traffic to new network traffic. If it finds that the new network traffic differs to much, it will report that there may be spyware on the computer, or some unwanted program using network resources.

It can be compiled by simply running make. It also requires that GTK+ 3 and the pkg-config programs are on the computer for it to work. After compiling simply run ./spyware-beware. The executable is also included in this repo if compiling proves difficult.
