# Guard Comms/Guard Stomping - Abusing Windows Guard Pages for C2 Communications
Author: AsaurusRex

## Purpose
This is a project showcasing some Userland techniques related to abusing guard pages for C2 communications, namely Guard Comms and Guard Stomping. You can find the public talk on this topic here: (Link to follow).

## Guard Comms
Guard Comms is a technique where your post exploitation module will create a new RW section in memory, write the desired data to it along with a header and footer, and then change the memory permissions to RW + G before exiting. Your main c2 process can then crawl memory space looking at RW + G sections (looking for the header) to grab that data, before wiping and freeing the memory region. New regions could look suspicious since they aren't backed on disk, and sizing can become a problem, though less of a problem than with Guard Stomping.

## Guard Stomping
Guard Stomping is a technique similar to Guard Comms, except that it utilizes existing RW + G sections in memory to write data, and doesn't require new unbacked sections of memory. It can become more complex as these sections are needed by threads to prevent corruption normally, so you need to be careful how long/how much you dabble with them. It is a stealthier technique due to using backed memory, having normal guard page sizes for regions, but comes with more sizing restrictions (each region is usually 12kb).  You can try to spin up more legitimate threads to create more regions, but again, beware stack corruption.

## Requirements:
You should be able to build this C++ code on any standard Windows system, I tend to use Visual Studio and build on a Windows 11 machine.

## Op Sec Considerations
This code should not be considered opsec safe, as I am using basic loading techniques to load post-exploitation modules which should be considered "loud." This is a technique which works well with any loading method you choose, whether reflective loading, shellcode, etc. Please watch the talk to see how this technique can be utilized.

## Example
Both the Guard Comms and Guard Stomping Code is designed to run a post exploitation module around a process list. You can write your own custom post exploitation modules and incorporate them with these techniques pretty trivially, simply replace process_list data with whatever data you are trying to fetch.

## Future Works
I may publish a follow up blog post discussing these and other uses in the near future. 


