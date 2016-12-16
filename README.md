lkafilter
========

This netfilter module was an assignment from the University of California Santa Cruz Extension Advanced Linux Kernel Programming class. It was developed using Linux v3.12, which is significant because the netfilter API has undergone numerous tweaks, and when I went back to work on the project bit I was running on v3.19 and had to make some minor changes (see [Netfilter API Changes](#aa) for a list of changes through v4.8). Given that this was developed in a classroom timeframe, there are many things that would have to be done were it to become real Linux production code. It is however more complex than the few samples I found when researching netfilter and therefore may be useful. 

The assignment was simple: develop a netfilter module and test it with [nweb](https://sourceforge.net/projects/nmon/files/?source=navbar). For extra credit, modify the Linux kernel to add a small feature. Like the main assignment, the details of the feature were left to the student, but the professor was interested in seeing a single call for registering multiple hooks. From studying the code it was clear that such a feature had already been implemented, and instead I added the variation discussed in [Core Extension](#ab). 

A good, although dated, overview of netfilter can be found at [netfilter](http://www.netfilter.org/documentation/HOWTO/netfilter-hacking-HOWTO.html). The purpose is to allow code that provides complex networking capabilities to 'hook' into the mainline packet processing at various points to examine, modify, and possibly drop inbound and outbound packets. Security, NAT, connection tracking and other features all use netfilter hooks. Linux defines several points for inspection such as NF_INET_PRE_ROUTING, and several actions that a hook routine can specify such as NF_DROP. Actions and Hook enumerations can be found in the Linux source tree at include/uapi/linux/netfilter.h.

Overview
-----------------

The lkafilter module (named after the 'lka' Linux-Kernel-Advanced prefix used by the professor) is built from two C source files, a header file, and a Makefile. The 'kh' prefix is the author's initials. *khfilter.c* contains the module initialization and cleanup code along with the netfilter processing structures and logic. *khrules.c* is the code that parses the filter rules strings into rules structures and uses those structures for packet inspection at runtime. *khfilter.h* contains the structures, definitions and exported prototypes for the module.   

Linux provides a rich and widely-used facility for managing network traffic based on the ip_tables packet filter and userspace program [iptables](http://netfilter.org/projects/iptables/index.html). lkafilter uses a simpler mechanism where rules are strings written in an *<action\><hook\><sequence\_of\_directives\>* format (see [lkafilter Rules](#ac) for a detailed description). This version hard-codes the rules and only supports Add/Drop actions and NF_INET_PRE_ROUTING and NF_INET_POST_ROUTING hooks, although the code is designed to be extensible. Rules could be supplied to the module in a file or by using a mechanism such as netlink sockets (or even ioctls). (Note that any dynamic rules management would require appropriate synchronization; RCU should be considered).   

The initialization code calls add_rule() for each rule string, building the lists that will be checked during runtime packet processing when the hook functions are called. It populates the nf_hook_ops structure with the information about the hooks and when they should be called, and then registers them. The current implementation has two callback functions, both of which are called for each packet. Each uses the hook type to locate its appropriate rule list. The first accepts all packets that match a rule on the list. The second drops all packets that have a rule match. A more efficient but less modular design would collapse both callbacks into a single handler, but the gain wouldn't be significant. 

The rule structure defined in khfilter.h has a list\_head, a set of fields that may be set with values for matching, and a bit mask that indicates whether a packet with a matching field matches the rule (bit set) or not (bit cleared). This means that without extending the design, the size of the bit mask determines the number of inspection fields, rules can't check for zeroed field values, and a rule can only have a single value for a given field. Nonetheless, a set of complex checks can be done by combining multiple rules and using the logic described in the following section.

*lkafilter* was developed as a tool for learning about netfilter, and it still has some code used during my explorations. In addition to printk code that allowed progress checking via *dmesg | tail -n* for some appropriate value of 'n', packet logging provided evidence of match/non-match conditions. Additionally, after the class ended I added code for hooking and logging packets for the NF_INET_LOCAL_IN and NF_INET_LOCAL_OUT cases. I was interested in tracking skbs through the hooks and getting a better idea of hook ordering. The debug messages are cryptic and only suitable for quick and dirty fact finding! But the code is left in for anyone who wants to play with it.

Two module\_params allow some minor configuration:
*dolog* must be set to 1 to enable packet dumping for the LOCAL\_IN and LOCAL\_OUT cases described above.   
*dodrop* must be set to 1 to cause the rules engine to actually drop the packets. If it is left at the default (0), a message will be generated to indicate the the packet would have been dropped but was actually accepted. This was particularly important for testing in a (single) VirtualBox configuration.    

Finally, the initial assignment was tested using the nweb tool, but subsequently I created a pair of simplistic Python scripts for generating small amounts of traffic between my Linux and Windows systems. *nf\_TCPclient.py* transmits a small file to *nf\_TCPserver.py*. This allowed me to quickly generate packets that met or failed the rule matching.  

  
<a name="ac"></a>Rules Strings
-----------------

This is a very simplistic firewall which only has PRE and POST_ROUTING hooks, and can only accept or drop a packet. Only xx.xx.xx.xx formatted ip addresses are accepted, and a protocol must be specified by its numeric value. Currently only the protocol (UDP or TCP), source and destination ports, and source and destination addresses are considered, and numbers  must be specified as decimal values.  
  
It has its own rules infrastructure, with unparsed rules having the form <action\><hook\><sequence\_of\_directives\>, where the sequence_of_directives takes the form of one or more <[+-]\><field\><value\> triples. A rule can only have one setting for each of the tracked fields. If a selected packet matches the '+' field(s), or doesn't match the '-' field(s), the rule is considered matched and the default action for the command type will be taken.  
Rule string format:  
  s[0]=A/D A=on a match, accept the packet, D= drop it  
  s[1]=direction I=inbound,first hook, O=outbound, last hook  
  s[2]=one of '+' or '-', indicating whether value equality means a rule match or non-match   
  s[3-4]  field specifier, one of sp,dp for source/destination port, sa,da for source/destination address, or pr for protocol.   
  s[5-?]   The data to compare, for some appropriate size and format  
  
Multiple conditions can be put together with no spaces to form a single rule. For example,"AI-sa10.0.0.15+pr6" means "accept anything TCP not from 10.0.0.15"

The sequence  
AI+pr6  
AI+pr17  
DI-dp8181  
says 'allow all TCP and UDP packets, but drop anything that doesn't have a destination port of 8181. 

The current design processes _A_ rules first, stopping with the first match, then _D_ rules. This would need to be studied to incorporate actions for other hooks. The processing logic walks through the specified rules list returning _true_ if a match with any rule is found and _false_ otherwise.  
  
Finally, the actions have their own match and default return values. _A_ matches produce NF_ACCEPT, with a non-match default of NF_DROP. _D_ matches are the reverse. It is likely that the default for any other actions should be NF_ACCEPT on the non-match case, but that has not been researched.


The design is intended to allow extension beyond the current fields. The field specifier could be expanded to include other fields or custom comparators. For example, DI+cuXXX could mean use XXX as an index into a table of registered functions that would do deeper packet inspection. This hasn't been implemented yet.  


<a name="aa"></a>Netfilter API Changes
-------------------  

The changes identified here come from analyzing
http://lxr.free-electrons.com

Note the hooks are called from nf_iterate() in core.c, using `struct nf_hook_ops **elemp` where elemp is set by walking the list
of registered ops structures for the hooknum in question (all other parameters will have been passed into nf_iterate). The call in
3.11 was misleading: the hooknum was not passed in, it was the address of the hook function.  

v3.11 call: `verdict = (*elemp)->hook(hook, skb, indev, outdev, okfn);` 

     typedef unsigned int nf_hookfn(unsigned int hooknum,
                                    struct sk_buff *skb,  
                                    const struct net_device *in,  
                                    const struct net_device *out,  
                                    int (*okfn)(struct sk_buff *));  

v3.13 call: `verdict = (*elemp)->hook(*elemp, skb, indev, outdev, okfn);` 

     typedef unsigned int nf_hookfn(const struct nf_hook_ops *ops,
                                    struct sk_buff *skb,  
                                    const struct net_device *in,  
                                    const struct net_device *out,  
                                    int (*okfn)(struct sk_buff *));  


v4.1 struct state was introduced, bundling several parameters; call: `verdict = (*elemp)->hook(*elemp, skb, state);`
  
     typedef unsigned int nf_hookfn(const struct nf_hook_ops *ops,  
                                struct sk_buff *skb,  
                                const struct nf_hook_state *state);  

v4.4 call: `verdict = (*elemp)->hook((*elemp)->priv, skb, state);`
  
     typedef unsigned int nf_hookfn(void *priv,  
                                struct sk_buff *skb,  
                                const struct nf_hook_state *state);  

Since lkafilter hooks rely on the hook number during processing, a move to v4.4 would require extracting it from struct state.   
Also: `struct module *owner` dissapeared from the ops structure in v4.4
The void \* priv member was added in v3.13

<a name="ab"></a>Core Extension
-------------------  

The code for registering, unregistering, and calling nethooks is contained in linux/net/netfilter/core.c, with nf_iterate() being the function that ultimately calls the hooks at various stages of packet processing. core.c defines a 2-dimensional array of list_heads such that each registered protocol has a list_head for each of the defined nethook types .   When networking code registers hooks, it does so by providing one or more nf_hook_ops structures, each containing among other things the hooknum (an integer representing the stage of packet processing for which the hook should be called), the hook a.k.a the callback function, and a list_head allowing the structure to be saved on one of the netfilter per-hooknum lists.  Invoking code actually calls one of a set of inline functions contained in netfilter.h, with NF_HOOK() being the most frequently called. When nf_iterate runs it accesses the list head for the particular hooknum and walks through the queued ops structures invoking their callback/hook functions. The list walking stops if a hook indicates that it has consumed the packet in some way.

The kernel extension created for lkafilter substitutes the address of a zero-terminated array of callback routines for that of the hook function. This is indicated to nf_iterate() by or'ing 0x1 with the address supplied for the hook in the registered ops structure, a 'safe' operation as long as hook is a word aligned pointer. When this condition is recognized, nf_iterate() walks through the array and calls each of the functions until the array is exhausted or the packet is not accepted.

The benefit of this change is that no other hooks could be inserted between the functions in the array. The core.c code that registers multiple hooks supplied in an array drops its locks between adding each structure provided in the nf_hooks_op array so that the registration isn't 'atomic'. This functionality could be replicated by having the hook callback function itself run down through an array of function pointers in its netfilter module at the cost of adding complexity to the hook function. If such functionality were ever desired it can be argued that centralizing it in core.c would be the cleanest and it is a simple change:

    list_for_each_continue_rcu(*i, head) {  
        struct nf_hook_ops *elem = (struct nf_hook_ops *)*i;  
        if (hook_thresh > elem->priority)  
            continue;  
    #ifdef CONFIG_CHAINED_HOOKS  
        //If the lsb of the elem->hook is set, it is really a null-terminated  
        //array of function pointers that only return NF_ACCEPT or NF_DROP  
        if (elem->hook &0x1) { //valid function pointer will never pass this test  
            chain = (nf_hookfn **)(((unsigned int)elem->hook) & (~0x1));   
            j = 0;  
            while(chain[j]) {   
                verdict = (*chain[j])(hook, skb, indev, outdev, okfn);  
                j++;  
                if (verdict != NF_ACCEPT)  
                    return verdict;  
            }  
            continue; //to the next hook function  
        } 
    #endif  
    verdict = elem->hook(hook, skb, indev, outdev, okfn);  
    if (verdict != NF_ACCEPT) {  

Gotchas related to this of course are that the result of the 'or' is a bad pointer, but this approach is used elsewhere in the kernel. Also it is important not to do anything that would compromise the behavior of the networking stack in general, or the RCU list walking of the hook queue (e.g. don't sleep, be quick). But that is a requirement for hook functions in general and is not specific to this change.

As shown above, the extension code in both lkafilter and core.c is indicated with \#ifdef CONFIG_CHAINED_HOOKS. It would be handy to allow the feature to be additionally disabled at run-time so that the hook would be ignored, at either the point of registration or when the hook is invoked, but this is just another TODO item.
