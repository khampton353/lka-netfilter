/* khfilter header file */

#ifndef KHFILTER_H
#define KHFILTER_H

#include <linux/kernel.h> //also provides printk macros
#include <linux/netfilter.h>
#include <net/ip.h> //really not needed, its included by tcp.h and udp.h
#include <net/tcp.h>
#include <net/udp.h>
#include <linux/netfilter_ipv4.h>

#define MAXALLOWED 0xFFFF


#ifdef CONFIG_CHAINED_HOOKS 
#define NUM_CHAIN_FUNCTIONS 2
#define NUM_HOOKS 4
#else
#define NUM_HOOKS 6
#endif

/* values for bit mask in rule.
 * for the given item, a set bit means the rule is matched if the packet 
 * matches the item. A cleared bit means the rule is matched if the packet
 * doesn't match the item.
 */

#define is_proto 1 
#define is_sport 2
#define is_dport 4
#define is_saddr 8
#define is_daddr 16
//#define is_custom xx

/* indices into array of lists holding parsed rule structures */

#define IN_KEEP    0 //AI rules
#define IN_NOKEEP  1 //DI rules
#define OUT_KEEP   2 //AO rules
#define OUT_NOKEEP 3 //DO rules

/* rule structure for hook handlers. rules are created from the rule strings 
 * and  added to the appropriate queues for packet processing. Current 
 * queues support the A/D I/O comparisons. This could be extended for other
 * actions and hooks. For example DI+cuXXX could mean use XXX as an index into 
 * a table of registered functions that would do deeper packet inspection, 
 * with the index being stored in the rule structure.
 */
struct rule {
        struct list_head rlist;  //for adding to the correct q
        uint matchbits;          //one per specifier, set bit: +, cleared: -
        uint sport;              //source port
        uint dport;              //destination port
        uint saddr;              //source address
        uint daddr;              //destination address
        uint proto;              //protocol
	/*uint idx;*/            //placeholder, index into function pointers 
                                 //array for custom rule extensions
};

/* processes a rule string, creates a struct rule and puts it on the 
 * correct rule queue. returns 0 on success
 */
extern int add_rule(char* rulestr, struct list_head *rlists);

/* this does the real work of matching the rules to the packet. 
 * it could get much more clever if it had an array of custom 
 * inspectors to process...
 * Note that this function makes no decision about the action, it
 * only looks for a match between the rule and the packet
 * The logic is this:
 * If the rule has a field that compares == to the packet field, and the 
 * appropriate bit is set in the matchbits field, that part of the rule is
 * a match. But if the fields compare == and the matchbits bit is not set,
 * the rule fails; this is the 'anything BUT this' case.
 * Note the assumption that the rule cannot be empty, but if it is the packet
 * will be assumed to match, equating to an accept all or drop all depending on 
 * whether the rule comes from the A_lst or the D_lst (see search_rules())
 */
extern bool match_rule (struct rule *r,  struct sk_buff *skb); 

#endif


