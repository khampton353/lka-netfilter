/* Kathryn Hampton 
 * simple firewall program that can optionally be built to work with
 * a net/netfilter/core.c extension that allows passing an array of function
 * pointers in place of the standard hook function pointer
 *
 * This implementation uses the hook callback API found in Linux v3.13-v4.0.
 */


#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/version.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/list.h>

#include "khfilter.h"   /*rule definitions, netfilter #includes*/


MODULE_DESCRIPTION("simple firewall with rule configuration");
MODULE_AUTHOR("Kathryn Hampton");
MODULE_LICENSE("GPL");

/* dodrop controls whether packets actually get dropped or - the
 * default - a printk says they would get dropped but they really
 * are retained with a return code of return NF_ACCEPT
 */
static int dodrop = 0;   //insmod lkafilter.ko dodrop=1 really drops packets
module_param(dodrop, int, S_IRUGO);

/* dolog controls logging of NF_INET_LOCAL_IN and NF_INET_LOCAL_OUT packets
 * for debugging purposes.This could easily be turned into dynamic thing by 
 * using procfs or netlink sockets to configure it 
 * default - don't log
 */
static int dolog = 0;   //insmod lkafilter.ko dolog=1 logs these packets
module_param(dolog, int, S_IRUGO);

/* GLOBAL DECLARATIONS */

//hardcoded rules strings
char *rules[]=	{"AI+dp8181", //accept rcv if dp is 8181
		"AI+dp8182", //accept rcv if dp is 8182
		"AI-sa10.0.0.15+pr6", //accept anything TCP not from 10.0.0.15
		"DI+dp8183",  //drop anything for destination port 8183
		"AO+pr6", //accept only TCP output
		 0
};

/* lists for rule action/direction categories. 'Direction' is appropriate for
 * this simplistic example, but really represents the hook type.
 */
struct list_head rule_lists[4]; //for AI rules, DI rules, AO rules, DO rules 

#ifdef CONFIG_CHAINED_HOOKS
/* structures for the arrays of function pointers to be passed in the 
 * nf hook ops registration
 */
nf_hookfn **chain = NULL;
#endif

/* the structure to pass to nf_register_hooks */
struct nf_hook_ops *filter_ops_;

/* OVERVIEW
 *
 * This is a very simplistic firewall which only has PRE and POST_ROUTING 
 * hooks, and can only accept or drop a packet. Currently only the protocol 
 * (UDP or TCP), source and destination ports, and source and destination 
 * addresses are considered. Numbers must be specified as decimal values, 
 * only xx.xx.xx.xx formatted ip addresses are accepted, and a protocol must 
 * be specified by its numeric value. However the design is intended to be
 * extensible, even allowing customized deep packet inspection.
 *
 * It has its own rules infrastructure, with unparsed rules having the form 
 * <action><hook><sequence_of_directives>, where the sequence_of_directives
 * takes the form of one or more <[+-]><field><value> triples. 
 *
 * A rule can only have one setting for each of the tracked fields. If a 
 * selected packet matches the '+' field(s), or doesn't match the '-' field(s),
 * the rule considered matched and the default action for the command type 
 * will be taken
 * Format:
 *  s[0]=A/D A=on a match, accept the packet, D= drop it
 *  s[1]=I/O I=inbound/NF_INET_PRE_ROUTING, O=outbound==NF_INET_POST_ROUTING
 *  s[2]='+' or '-', + means a match if the packet field equals the specified
 *          data value, - means a rule match if the packet field is unequal
 *  s[3-4]  field specifier, one of sp,dp for source/destination port,
 *          sa,da for source/destination address, and pr for protocol.
 *  s[5-?]  data value to compare to the packet, for some appropriate size and format
 *
 * Multiple conditions can be put together in a single rule with no spaces, 
 * thus "AI-sa10.0.0.15+pr6" means "accept anything TCP not from 10.0.0.15"
 *
 * The sequence
 * AI+pr6
 * AI+pr17
 * DI-dp8181
 * says 'allow all TCP and UDP packets, but drop anything that doesn't have a
 * destination port of 8181. The current design processes 'A' rules first,
 * stopping with the first match, then 'D' rules. This would need to be studied
 * to incorporate actions for other hooks.
 *
 * Finally, the actions have their own match and default return values. 'A'
 * matches produce NF_ACCEPT, with a non-match default of NF_DROP. 'D' matches
 * are the reverse. It is likely that the default for any other actions should
 * be NF_ACCEPT on the non-match case, but that has not been researched.
 *
 * In this implementation the rules are hard coded and are are parsed into 
 * 'struct rule' structures stored in a series of queues appropriate to the hook 
 * and action types.
 *
 *
 * TODO list (partial :)
 * Update for the >=v4.1 api; minimal impact to this code.
 * 
 * support for collecting statistics, and counters to
 * keep track of them
 *
 * better management of printk's, including appropriate levels and
 * the ability to compile them out. This is a home-grown dev version
 *
 * ipv6, more addressing flexibility, etc etc
 *
 * the parsing engine should use uapi/linux/netfilter.h enumerations for
 * the action and hook fields instead of the current character values
 *
 * dynamic, user-supplied, extensible rules, with the error checking and
 * synchronization that comes along with that. For example a rule string 
 * such as "DI+cuXXX" could mean use XXX as an index 
 * into a table of registered inspection functions, and drop any incoming 
 * packets that return a match.
*/



/*** Start of Functions ***/

/* walk through the specified rule list checking to see if the packet matches
 * any rule, returning true at the first match, or false for an empty list or
 * for no match with the list
 */
static bool process_rule_list(struct list_head *lst, struct sk_buff *skb) 
{
	struct list_head *tmp, *tmp2;
	struct rule* r;
	bool ismatch;

	list_for_each_safe(tmp, tmp2, lst) {
			r = list_entry(tmp, struct rule, rlist);
			/*printk (KERN_ALERT "processing %p\n",r);*/
			ismatch = match_rule(r, skb);

			/*if (ismatch) 
				printk(KERN_ALERT "skb %p: rule %p matched\n",
					skb,r);
			else printk(KERN_ALERT "skb %p: rule %p did not match\n", 
				skb,r);
			*/
			if (ismatch) return true;
		}
	return false;
}

/* any overall packet validation goes here. return 'true' if it is a packet 
 * that might be of interest, in our case, a UDP or TCP packet
 */
static bool is_packetOK(struct sk_buff *skb)
{
	const struct iphdr *iph = ip_hdr(skb);
	struct udphdr _hdr, *hp = NULL;

	if (iph->protocol != IPPROTO_UDP && iph->protocol != IPPROTO_TCP) {

		printk(KERN_ALERT "Got some packet, protocol %u\n", iph->protocol);
		return false; //someone elses packet...
	}

	hp = skb_header_pointer(skb, ip_hdrlen(skb),
		sizeof(_hdr), &_hdr);
	if (hp == NULL)
		return false; //someone elses problem

	return true;
}

/* utility/debug routine for checking out the packet*/
static void dumpp(int rlist, struct sk_buff *skb){
	const struct iphdr *iph = ip_hdr(skb);
	struct tcphdr _hdr,*hp = NULL;
	hp = skb_header_pointer(skb, ip_hdrlen(skb),
                                         sizeof(_hdr), &_hdr);
	printk(KERN_ALERT "%s PKT -%d-,%p, dport: %u,sport: %u, "
		"daddr: %pI4, saddr: %pI4 SEQ: %u\n",
		rlist==IN_KEEP?"IN":"OTH",rlist,skb,
		ntohs(hp->dest),ntohs(hp->source),&iph->daddr,
		&iph->saddr, ntohs(hp->seq)); 
}

/* hook function that really is a debug/logging routine for 
 * NF_INET_LOCAL_IN/OUT. The hooknum is bumped for easy recognition in a log
 */
static unsigned int do_log(
	const struct nf_hook_ops *ops,
        struct sk_buff *skb, const struct net_device *in,
        const struct net_device *out, int (*okfn)(struct sk_buff *))
{	
	if (!dolog)
		return true;
	printk(KERN_ALERT "DO_LOG %d  ",ops->hooknum);
	dumpp(ops->hooknum+10,skb);
	return true;
}

/* handler for 'A' queue rules, input or output*/
static unsigned int do_accept(
	const struct nf_hook_ops *ops,
        struct sk_buff *skb, const struct net_device *in,
        const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	int tmp;
	if (!is_packetOK(skb))
		return NF_ACCEPT; //someone else's packet/problem
	if (ops->hooknum == NF_INET_PRE_ROUTING)
		tmp = IN_KEEP;
	else
		tmp = OUT_KEEP;
	dumpp(tmp,skb);

	if (!list_empty(&rule_lists[tmp]) && !process_rule_list(&rule_lists[tmp], skb)) {
		//no matches in the _keep list, have to drop
		printk(KERN_ALERT "%s: would drop - A\n",
			tmp==IN_KEEP?"IN":"OUT");
		if (dodrop)
			return NF_DROP;
		return NF_ACCEPT; //should be return NF_DROP;
	}
	printk(KERN_ALERT "%s: would accept - A\n",
		tmp == IN_KEEP ? "IN" : "OUT");
	return NF_ACCEPT;
}


/* handler for 'D' queue rules, input or output*/
static unsigned int do_drop(
	const struct nf_hook_ops *ops,
       struct sk_buff *skb, const struct net_device *in,
       const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	int tmp;
	if (!is_packetOK(skb))
		return NF_ACCEPT; //someone else's packet/problem
	if (ops->hooknum == NF_INET_PRE_ROUTING)
		tmp = IN_NOKEEP;
	else
		tmp = OUT_NOKEEP;

	if (process_rule_list(&rule_lists[tmp], skb)) {
 		// a match here means return NF_DROP
		printk(KERN_ALERT "%s: would drop - D - skb %p\n",
			tmp == IN_NOKEEP ? "IN_NO" : "OUT_NO",skb);
		if (dodrop)
			return NF_DROP;
		return NF_ACCEPT; //should be return NF_DROP;
	}
	printk(KERN_ALERT "%s: would accept - D - skb %p\n",
		tmp == IN_NOKEEP ? "IN_NO" : "OUT_NO",skb);
	return NF_ACCEPT;
}


//remove any rules from the list and free the memory
static void clean_list(struct list_head * lst) 
{
	struct list_head *tmp, *tmp2;
	struct rule* r;
	list_for_each_safe(tmp, tmp2, lst) {
			r = list_entry(tmp, struct rule, rlist);
			list_del(&r->rlist);
			printk (KERN_ALERT "freeing %p\n",r);
			kfree(r);
		}

}

/* release any allocated resources */
static void clean_(void) 
{
	clean_list(rule_lists+IN_KEEP);
	clean_list(rule_lists+IN_NOKEEP);
	clean_list(rule_lists+OUT_KEEP);
	clean_list(rule_lists+OUT_NOKEEP);
#ifdef CONFIG_CHAINED_HOOKS
	if (chain)
		kfree(chain);
#endif
	if (filter_ops_)
		kfree(filter_ops_);
}

/* parse rules to create the rules lists. For now this just translates the 
 * hard-coded rules strings and is a place holder for whatever more 
 * sophisticated handling evolves. Returns the count of rules successfully
 * added.
 */
static int add_rules(char **rules) 
{
	int cnt=0;
	while (*rules)
		cnt += add_rule(*rules++,rule_lists)?0:1;
	return cnt;
}

/* set up the hook ops structure entries for registration*/
static void init_ops(struct nf_hook_ops *ops)
{
	int i;

#ifdef CONFIG_CHAINED_HOOKS
	unsigned int hk= ((unsigned int)chain) | 0x1; //signal nf_iterate that this is a chain

	ops[0].hook = (nf_hookfn *)hk;
	ops[0].hooknum = NF_INET_PRE_ROUTING;
	ops[1].hook = (nf_hookfn *)hk;
	ops[1].hooknum = NF_INET_POST_ROUTING;
	ops[2].hook = do_log;
	ops[2].hooknum = NF_INET_LOCAL_IN;
	ops[3].hook = do_log;
	ops[3].hooknum = NF_INET_LOCAL_OUT;
#else
	ops[0].hook = do_accept;
	ops[0].hooknum = NF_INET_PRE_ROUTING;
	ops[1].hook = do_drop;
	ops[1].hooknum = NF_INET_PRE_ROUTING;
	ops[2].hook = do_accept;
	ops[2].hooknum = NF_INET_POST_ROUTING;
	ops[3].hook = do_drop;
	ops[3].hooknum = NF_INET_POST_ROUTING;
	ops[4].hook = do_log;
	ops[4].hooknum = NF_INET_LOCAL_IN;
	ops[5].hook = do_log;
	ops[5].hooknum = NF_INET_LOCAL_OUT;
#endif
	for (i=0; i < NUM_HOOKS; i++) {
		ops[i].owner = THIS_MODULE; //not used after Linux 4.3
		ops[i].pf = NFPROTO_IPV4;
		ops[i].priority = NF_IP_PRI_FILTER;
	}

}

/* module initialization routine */
static int __init khfilter_init(void)
{
	int ret;

	printk(KERN_ALERT "khfilter main initializing! dodrop is %d\n",
		dodrop);

	INIT_LIST_HEAD(rule_lists+IN_KEEP);
	INIT_LIST_HEAD(rule_lists+IN_NOKEEP);
	INIT_LIST_HEAD(rule_lists+OUT_KEEP);
	INIT_LIST_HEAD(rule_lists+OUT_NOKEEP);

	ret= add_rules(rules);
	printk(KERN_ALERT "lkafilter added %d rules\n",ret);
	if (!ret){
        	ret = -EINVAL;
		goto err;	
	}
#ifdef CONFIG_CHAINED_HOOKS
	chain = kzalloc((NUM_CHAIN_FUNCTIONS + 1) * sizeof(nf_hookfn *),
				GFP_KERNEL); 

	printk(KERN_ALERT "chain address is %p\n", chain);

	if (!chain) {
		ret = -ENOMEM;
		goto err;
	}

	chain[0] = do_accept;
	chain[1] = do_drop;
	chain[2] = NULL;
#endif
	filter_ops_ = kzalloc(((NUM_HOOKS + 1) * sizeof(struct nf_hook_ops)), 
		GFP_KERNEL);
	if (!filter_ops_) {
                ret = -ENOMEM;
                goto err;
        }

	init_ops(filter_ops_);	

	printk(KERN_ALERT "filter_ops_[0].hook is %p and do_accept is %p\n",
			filter_ops_[0].hook, do_accept);  


	ret = nf_register_hooks(filter_ops_, NUM_HOOKS);

	if (!ret)
		printk(KERN_ALERT "khfilter init done: %d\n",__LINE__);
	else { 
		printk(KERN_ALERT "khfilter init failed with %d: %d\n", 
			ret,__LINE__);
		goto err;
	}
	return 0;
err:
	clean_();
	return ret;
}

/* cleanup on removal*/
static void khfilter_exit(void)
{
	nf_unregister_hooks(filter_ops_, NUM_HOOKS);

	clean_();

	printk(KERN_ALERT "khfilter exit\n");

	return;
}



module_init(khfilter_init);
module_exit(khfilter_exit);


