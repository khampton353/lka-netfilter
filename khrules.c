/* rule parsing routines for khfilter.c */

#include <linux/module.h>
#include <linux/kernel.h>
#include "khfilter.h"
#include <linux/ctype.h>



/* extract an integer from decimal digits embedded in the string. Limits size  
 * to U16_MAX as a sanity check. simple_strtol]() would be great if not marked
 * obsolete, kstrtol() requires the str to null terminate after the digits and 
 * doesn't indicate number of characters consumed, so we can't use them. 
 * sets *ptarget to the integer if valid and returns the number of chars 
 * consumed or any error. *ptarget is set to zero and left that way if there 
 * no valid digits in the string or if i exceeds a threshold max.
 * expects the integer in the string to be in the correct  range to fit  
 * *pTarget, but limits it to maxm
*/
static int get_integer(char* str, unsigned int *ptarget, int maxm)
{
	int i = 0; //for count of chars consumed
	unsigned int tmp = 0;

	*ptarget = 0;
	if (maxm > U16_MAX) //nothing we currently want exceeds this
		return -EINVAL;
	while (str[i] && isdigit(str[i]) && (tmp <= maxm)) {
		tmp = (tmp * 10 + (str[i] - '0'));
		++i;
	}
	if (i && (tmp <= maxm))
		*ptarget = tmp;
	else
		i = 0 - i; 
	printk(KERN_ALERT "get_integer returning %x\n", *ptarget);
	return i; //non-zero if overflow but *ptarget will be 0
}


/* rudimentary string conversion for ipv4 address
   assumes caller knows the string is valid
   returns the number of consumed characters
   with paddr set to the converted value (or 0)
   only supports decimal a.b.c.d formatted ip addresses for now
*/
static int get_ip(char* str, unsigned int *paddr)
{
	unsigned int val = 0;
	int i, j,cnt=0;
	unsigned int tmp=0;

	*paddr=0;

	j=4;
	while (j) {
		printk(KERN_ALERT "getip octet %d, cnt=%d, val=%d", j,cnt,val);
		i = get_integer(str + cnt, &tmp, U8_MAX);
		if (i < 1) //0 or negative
			break;
		val=(val << 8) + tmp;
		--j;
		if (j) //don't consume the character following the addr
			++i;
		cnt+=i;
	} //while j
	if (j==0) 
		*paddr=val; //addr is 4 valid octets, update *paddr
	printk (KERN_ALERT "getip returning cnt=%d for %x\n", cnt,*paddr);
	return cnt;
}



/* returns the number of chars to advance the string, or 0 if the
 * rule is not valid; updates the rule structure with the results
 * msk indicates whether to set a rule '+' or '-'
 */
int lka_get_rule(char *rstr, struct rule *r, int msk, int len)
{
	int cnt = -2;   //chars to advance, 2 are added before
					//returning, returning 0 for invalid rule 
	unsigned int tmpval = 0;
	int c0, c1; //rule codes are 2 characters

	if (len < 3) return 0; //can't even be a protocol
	c0 = rstr[0];
	c1 = rstr[1];
	rstr += 2; //advance past type field

	if ((c0 == 'p') && (c1 == 'r')) { //protocol		
		cnt = get_integer(rstr, &tmpval, U8_MAX);
		if (!tmpval)
			return 0;
		r->proto = tmpval;
		r->matchbits |= (msk & is_proto);
	}
	else if ((c0 == 's') || (c0 == 'd')) { //source or dest
		if (c1 == 'p') {  //port 
			cnt = get_integer(rstr, &tmpval, U16_MAX);
            if (!tmpval)
				return 0; //port cant be 0
            if (c0 == 's') {
	            r->sport = tmpval;
                r->matchbits |= (msk & is_sport);
			} else {
				r->dport = tmpval;
				r->matchbits |= (msk & is_dport);
			}
		}
		else if (c1 == 'a') { //ip addr
			cnt = get_ip(rstr, &tmpval);
			if (!tmpval)
				return 0;
			if (c0 == 's') {
				r->saddr = tmpval;
				r->matchbits |= (msk & is_saddr);
			}
			else {
				r->daddr = tmpval;
				r->matchbits |= (msk & is_daddr);
			}
		}
	} //source or destination for port/address 
	return cnt+2; //-2 +2 (0) if invalid rule type
}
  

/* processes a rule string, creates a struct rule and puts it on the 
 * correct rule queue. caller is responsible for determining that that 
 * the rule string is formatted properly
 * returns 0 on success
 */
int add_rule(char* rulestr, struct list_head *rlists)
{
	struct rule *newrule;
	int i, len, cnt=0, ret = 0;
	struct list_head *tmplist = NULL;
	uint msk = 0;

	newrule = (struct rule *)kzalloc(sizeof(struct rule), GFP_KERNEL);
	printk(KERN_ALERT "allocated %p\n", newrule);

	if (newrule == NULL)
		return -ENOMEM;

	INIT_LIST_HEAD(&newrule->rlist);

	if (rulestr[0] == 'A') {
		if (rulestr[1] == 'I')
			tmplist = rlists+IN_KEEP;
		else if (rulestr[1] == 'O')
			tmplist = rlists+OUT_KEEP;
	}
	else if (rulestr[0] == 'D') {
		if (rulestr[1] == 'I')
			tmplist = rlists+IN_NOKEEP;
		else if (rulestr[1] == 'O')
			tmplist = rlists+OUT_NOKEEP;
	}

	if (!tmplist) {
		ret = -EINVAL;
		goto err;
	}

	len = strlen(rulestr);
	len -= 2;
	i = 2; //skip the first two chars

	while (len > 0) {
		if (rulestr[i] =='+')
			msk=0xff;
		else if (rulestr[i] !='-') {
			//malformed rule
			printk (KERN_ALERT "Expected + or -, got %c at %d,"\
				"cnt = %d\n",
				rulestr[i], i, cnt);
			ret = -EINVAL;
			goto err;
		}
		len--;
		i++;
		cnt = lka_get_rule(&rulestr[i], newrule, msk, len);
		if (cnt == 0) { //string didn't advance, bad rule
			ret = -EINVAL;
			goto err;
		}
		len -= cnt;
		i += cnt;
		msk = 0;
	}

	printk (KERN_ALERT "Rule %s added, mask %x, vals %d %d %x %x %d\n",
		rulestr, newrule->matchbits, newrule->sport, newrule->dport, newrule->saddr,
		newrule->daddr, newrule->proto);

	//all done, put rule on the correct queue
	list_add_tail(&newrule->rlist, tmplist);
	return 0;
err:
	if (newrule)
		kfree(newrule);
	return ret;
}


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
bool match_rule (struct rule *r,  struct sk_buff *skb) 
{
	const struct iphdr *iph = ip_hdr(skb);
	struct udphdr _hdr,*hp = NULL;
	unsigned int be_r_saddr, be_r_daddr;//just printk

	hp = skb_header_pointer(skb, ip_hdrlen(skb),
					sizeof(_hdr), &_hdr);

	be_r_saddr=htonl(r->saddr);
	be_r_daddr=htonl(r->daddr);
	/*printk (KERN_ALERT "Checking rule. matchbits= %u, proto=%u, saddr=%pI4, "
		               "daddr=%pI4, sport=%u, dport=%u\n", r->matchbits, r->proto,
					&be_r_saddr, &be_r_daddr, r->sport, r->dport);
*/
	//check for a protocol match.
	if (r->proto) {
        /*        printk(KERN_ALERT "proto r: %u, p: %u, matchbits %u \n",
                        r->proto, iph->protocol, r->matchbits);
	*/
		if (((r->matchbits & is_proto) && (iph->protocol != r->proto)) ||
			(!(r->matchbits & is_proto) && (iph->protocol == r->proto)))
			return false;
	}
	//check for a source address match
	if (r->saddr) {
        /*        printk(KERN_ALERT "saddr r: %pI4, p: %pI4, matchbits %u \n",
                        &be_r_saddr, &iph->saddr, r->matchbits);
	*/
		if (((r->matchbits & is_saddr) && (ntohl(iph->saddr) != r->saddr)) ||
			(!(r->matchbits & is_saddr) && (ntohl(iph->saddr) == r->saddr)))
			return false;
	}
	//check for a destination address match
	if (r->daddr) { 
        /*        printk(KERN_ALERT "daddr r: %pI4, p: %pI4 matchbits %u \n",
                        &be_r_daddr, &iph->daddr, r->matchbits);
	*/
		if (((r->matchbits & is_daddr) && (ntohl(iph->daddr) != r->daddr)) ||
			(!(r->matchbits & is_daddr) && (ntohl(iph->daddr) == r->daddr)))
			return false;
	}
	//check for a source port match
	if (r->sport) { 
        /*        printk(KERN_ALERT "sport r: %u, p: %u, matchbits %u \n",
                        r->sport, ntohs(hp->source), r->matchbits);
	*/
		if (((r->matchbits & is_sport) && (ntohs(hp->source) != r->sport)) ||
			(!(r->matchbits & is_sport) && (ntohs(hp->source) == r->sport)))
			return false;
	}
	//check for a destination port match
	if (r->dport) { 
	/*	printk(KERN_ALERT "dport r: %u, p: %u, matchbits %u \n",
			r->dport, ntohs(hp->dest), r->matchbits);
	*/
		if (((r->matchbits & is_dport) && (ntohs(hp->dest) != r->dport)) ||
			(!(r->matchbits & is_dport) && (ntohs(hp->dest) == r->dport)))
			return false;
	}
	return true;
}
