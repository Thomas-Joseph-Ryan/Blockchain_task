# Blockchain Task

## How to run

Create a usage example similar to the one provided in usage_example.py

Then run this using python usage_example.py and examine the log files to see what has happened.

Each log file is named after the port number of a server runner and contains all of the output from that server.

Current log files and usage_example.py show the network sucessfully working with 7 server runners when 2 of them fail as 7
is the minimum number of responses required for consensus to be acheived when 2 nodes fail.

This example shows that the program still reaches consensus when 2 nodes fail and when 2 different nodes received messages
during the same consensus round meaning there are 2 valid blocks which could be committed.

By following the log files you can follow the story of how the nodes come to this agreement. The most interesting line of note is the logged line that is marked as [critical] as it shows what block has been decided on for that round

## Provided test cases

I also created some unit tests to test this system, to use these run

python -m unittest unittests

These take a few minutes to run but will pass eventually, these are basically a culmination of alot of different types
of usage examples.

## Why have I not provided prints to standard out (at least as of right now)

We have not been shown how we should do this yet, and in order to avoid a messy terminal I have opted to leave these out in
place of a logging system. You can ensure the system is working as expected through the usage_examples / unit tests, and then
examine each block and what has been accepted inside that block in the log files so I think that is acceptable.

Also, I was told by my tutor today 10/05/2023 that what we upload by friday will not be what is marked but rather what we
show in our tutorial, so if the tutor would like me to have print statements on that day then I will add them / sub them in 
for the logging statements

## Plagerism for network.py?

Just including this incase, since network.py was provided to us as a module to use, I am expecting this to show up as potential plagerism with other students