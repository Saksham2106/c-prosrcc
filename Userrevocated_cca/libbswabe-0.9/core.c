#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#ifndef BSWABE_DEBUG
#define NDEBUG
#endif
#include <assert.h>

#include <openssl/sha.h>
#include <glib.h>
#include <pbc.h>

#include "bswabe.h"
#include "private.h"

#define TYPE_A_PARAMS \
"type a\n" \
"q 87807107996633125224377819847540498158068831994142082" \
"1102865339926647563088022295707862517942266222142315585" \
"8769582317459277713367317481324925129998224791\n" \
"h 12016012264891146079388821366740534204802954401251311" \
"822919615131047207289359704531102844802183906537786776\n" \
"r 730750818665451621361119245571504901405976559617\n" \
"exp2 159\n" \
"exp1 107\n" \
"sign1 1\n" \
"sign0 1\n"

char last_error[256];

char*
bswabe_error()
{
	return last_error;
}

void
raise_error(char* fmt, ...)
{
	va_list args;

#ifdef BSWABE_DEBUG
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	exit(1);
#else
	va_start(args, fmt);
	vsnprintf(last_error, 256, fmt, args);
	va_end(args);
#endif
}

void
element_from_string( element_t h, char* s )
{
	unsigned char* r;

	r = malloc(SHA_DIGEST_LENGTH);
	SHA1((unsigned char*) s, strlen(s), r);
	element_from_hash(h, r, SHA_DIGEST_LENGTH);

	free(r);
}

bswabe_sigver_t* sigkeygen(bswabe_pub_t* pub){
	bswabe_sigver_t* pair = malloc(sizeof(bswabe_sigver_t));
	pair -> a = malloc(sizeof(bswabe_verification_t));
	pair -> b = malloc(sizeof(bswabe_sig_t));
	element_init_Zr(pair -> b -> x,pub -> p);
	element_random(pair -> b ->x);
				//single pairing initialization for all element_t type initialisation====> computed from above string s
				//exponentiation function used is element_pow_mpz
				//element_t g is initialized as G1 member instead of Zr
				//the char* member of bswabe_verification_t is uninitialised
	element_init_Zr(pair ->a -> y,pub -> p);
	element_random(pair -> a ->y);

	element_init_G2(pair -> a ->g,pub -> p);
	element_random(pair -> a->g);
	element_init_G2(pair -> a->g_y, pub -> p);
	element_pow_zn(pair -> a->g_y,pair -> a->g,pair -> a->y);
	element_init_G2(pair -> a->g_xy, pub -> p);
	element_pow_zn(pair -> a->g_xy,pair -> a->g_y,pair -> b -> x);//see here 
	pair -> a -> y_s = random_binaryString();
	return pair;
}

char* random_binaryString(){
	srand(time(0));
	char *s = (char*)malloc(128 * sizeof(char));
	int count = 0;
	while(count < 128){
		int x = rand();
		if(x % 2 == 0){
			s[count] = '0';
		}else{
			s[count] = '1';
		}
		count++;
	}
	return s;
}

/* Added by Ritik Aggarwal on 28th December */
bswabe_signature_t* sign(bswabe_sig_t *sig, bswabe_cph_t *cp, bswabe_pub_t *pub){

	bswabe_signature_t* signa;
	signa = malloc(sizeof(bswabe_signature_t));
	element_t tempp;
	element_t temp;
	// sigma = (C1 * C3 + C2)^x 	
	element_init_G1(signa -> sigma, pub -> p);
	element_init_G1(tempp, pub -> p);
	element_init_G1(temp, pub -> p);

	element_mul(tempp, cp -> c, cp -> c3);
	//element_add(tempp, temp, cp -> c);
	element_pow_zn(signa -> sigma, tempp, sig -> x);
 	return signa;
}

/* Added by Ritik Aggarwal on 29th December */
int verify(bswabe_verification_t *ver, bswabe_signature_t *signa, bswabe_cph_t *cp, bswabe_pub_t *pub){
	
	//element_printf("verification key is %B", ver -> g_xy);
	element_t pair1;
	element_t pair2;
	element_t temp;
	element_t tempp;
	element_init_GT(pair1, pub -> p);
	element_init_GT(pair2, pub -> p);
	//element_init_G1(signa -> sigma, pub -> p);
	element_init_G1(tempp, pub -> p);
	element_init_G1(temp, pub -> p);

	element_mul(tempp, cp -> c, cp -> c3);
	//element_add(tempp, temp, cp -> c);

	pairing_apply(pair1, signa -> sigma, ver -> g_y, pub -> p); 
	pairing_apply(pair2, tempp, ver -> g_xy, pub -> p);

	if(element_cmp(pair1,pair2) == 0){
		printf("\n-----verification MATCHES----------");
		return 1;
	}else{
		printf("\n-----verfication does not matches-----");
		printf("\n-----cannot decrypt--------");
		return 0;
	}

}

void
bswabe_setup( bswabe_pub_t** pub, bswabe_msk_t** msk ,int n)
{
	int M = 128;
	element_t alpha,temp,temp1,temp2,temp3,tempp;
	int i,j,k;
	/* initialize */
 	
	int m = /* insert the function */
 	printf("\n in core----after init \n");
	*pub = malloc(sizeof(bswabe_pub_t));
	*msk = malloc(sizeof(bswabe_msk_t));
	///assigning number of attributes to total_attr
	(*pub) -> count = 0;
	(*pub)->total_attr = n;
	printf("%d",(*pub)->total_attr);
	//printf("\n in core----after malloc \n");

	(*pub)->pairing_desc = strdup(TYPE_A_PARAMS);
	pairing_init_set_buf((*pub)->p, (*pub)->pairing_desc, strlen((*pub)->pairing_desc));
	//printf("\n in core----after init_set_buf \n");

	element_init_G1((*pub)->g1, (*pub)->p);
  	element_init_G1((*pub)->h, (*pub)->p);
	element_init_G1(temp, (*pub)->p);
	//element_init_G1(temp1, (*pub)->p);  /*just for checking*/
	//element_init_G1(tempp, (*pub)->p);  /*just for checking*/
	//element_init_Zr(temp2, (*pub)->p);  /*just for checking*/
	//element_init_Zr(temp3, (*pub)->p);  /*just for checking*/
	element_init_GT((*pub)->Y, (*pub)->p);
	element_init_Zr((*msk)->y, (*pub)->p);
	//printf("\n in core----after init of elements \n");

	element_random((*pub)->g1);
	element_random((*pub)->h);
	element_random((*msk)->y);
	//element_random(temp2);
	//element_random(temp3);
	//printf("\n in core----after value given to g1,h,y \n");

	element_pow_zn(temp, (*pub)->h, (*msk)->y);
	//printf("\n in core----after pow \n");

	/*element_pow_zn(tempp, (*pub)->g1, temp2);
	element_mul(temp1, temp,  tempp);
	element_pow_zn(temp1, temp1, temp3);
	element_printf("\nleft side= %B",temp1);

	element_pow_zn(tempp, (*pub)->g1, temp2);
	element_pow_zn(temp1, tempp , temp3 );
	element_mul(temp1, temp1, temp);
	element_printf("\nright side= %B",temp1);*/


	pairing_apply( (*pub)->Y , (*pub)->g1 , temp , (*pub)->p);
	
	//printf("\n after pairing \n");
	//element_printf("y = %B\n", (*msk)->y);
	//element_printf("temp = %B\n", temp);
	//element_printf("g1 = %B\n", (*pub)->g1);
  	//element_printf("h = %B\n", (*pub)->h);
  	//element_printf("Y = %B\n", (*pub)->Y);
	
	//sleep(2);
	printf("\n in core----before loop \n");
	for(i=0;i<n;i++)
	{
		for(j=0;j<3;j++)
		{
			element_init_Zr((*msk)->t[i][j], (*pub)->p);
			element_random((*msk)->t[i][j]);

			element_init_G1((*pub)->T[i][j], (*pub)->p);
			element_pow_zn((*pub)->T[i][j], (*pub)->g1, (*msk)->t[i][j]);
			//element_printf("\npub->T[%d][%d]= %B	\nmsk->t[%d][%d]=%B",i,j,(*pub)->T[i][j],i,j,(*msk)->t[i][j]);
		}
	}
	/* Added by ritik aggarwal on december 22, 2018 */
	for(k = 0;k<2*M;k++){
		element_init_Zr((*msk) -> u[k], (*pub) -> p);
		element_random((*msk) -> u[k]);
		element_init_G1((*pub) -> U[k],(*pub) -> p);
		element_pow_zn((*pub) -> U[k], (*pub) -> g1, (*msk) -> u[k]); 
		//element_printf("\npub->U[%d] = %B    \nmsk ->u[%d] = %B", k,(*pub) -> U[k], k, (*msk) -> u[k]);
	}
}

bswabe_prv_t* bswabe_keygen( bswabe_pub_t** pub, bswabe_msk_t* msk, char** attributes )
{
	int M = 128;
	bswabe_prv_t* prv;
	element_t r,temp;
	element_t sum;
	element_t h_y;
	char ch;
	int i,j,k;
	/* initialize */

	prv = malloc(sizeof(bswabe_prv_t));
	((*pub) -> count) = ((*pub) -> count) + 1;
	prv -> id = (*pub) -> count;
       // printf("\n in keygen----after malloc \n");
    /*
	element_printf("y = %B\n", (msk)->y);
	//element_printf("temp = %B\n", temp);
	element_printf("g1 = %B\n", (pub)->g1);
  	element_printf("h = %B\n", (pub)->h);
  	element_printf("Y = %B\n", (pub)->Y);
  	for(i=0;i<3;i++)
  		for(j=0;j<3;j++)
  			element_printf("\npub->T[%d][%d]= %B	\nmsk->t[%d][%d]=%B",i,j,(pub)->T[i][j],i,j,(msk)->t[i][j]);
  	*/
  	//printf("\n in keygen----after printing pub_key and master_key \n");

	element_init_G1(prv->d, (*pub)->p);
	element_init_G1(prv->d1,(*pub)->p);
	element_init_G1(temp, (*pub)->p);
	element_init_Zr(r,      (*pub)->p);
	element_init_Zr(sum,    (*pub)->p);
	element_init_G1(h_y,    (*pub)->p);


	//printf("\n in keygen----after init of prv->d g_r r sum h_y \n");
	prv->comps = g_array_new(0, 1, sizeof(bswabe_prv_comp_t));	

 	element_random(r);
	element_pow_zn(prv->d, (*pub)->g1, r);  ///g1^r
	//element_printf("\nd=%B",prv->d);
	//printf("\n in keygen----after g1^r \n");

	element_pow_zn(h_y, (*pub)->h, msk->y);
	
	/*for(i=0;i<3;i++)
		for(j=0;j<3;j++)
			element_mul(prv->d, msk->t[i][j], g_r);
	element_invert(y_inv, msk->y);
	element_pow_zn(prv->d, prv->d, y_inv);
	*/
	i=0;
	j=0;
	while( *attributes )
	{
		//printf("\n in keygen----in while \n");
		bswabe_prv_comp_t c;
		element_t h_rp;
		element_t rp;

		c.attr = *(attributes);
		printf("\nc.attr= [%c]",c.attr);
		printf("\nattributes from orig= [%s]",*(attributes));
		//strcpy(ch,*(attributes++));
		//printf("\nch= [%s]",ch);

		element_init_G1(c.d,  (*pub)->p);
		element_init_G1(c.dp, (*pub)->p);
		element_init_G1(h_rp, (*pub)->p);
		element_init_Zr(rp,   (*pub)->p);
		
 		if(strcmp(*(attributes),"1")==0 )
 		{
 			element_add(sum,sum,msk->t[i][j]);
 			//element_printf("\n in while core_keygen sum=%B ",sum);
 		}

		/*element_mul(c.d, g_r, h_rp);
		element_pow_zn(c.dp, pub->g1, rp);

		element_clear(h_rp);
		element_clear(rp);*/

		g_array_append_val(prv->comps, c);

		j++;
		if(j%3==0)
		{
			j=0;
			i++;
		}
		*(attributes++);
	}
	//element_printf("\n in core_keygen sum=%B ",sum);

	element_pow_zn(temp, (*pub)->g1, sum);
	//element_printf("\n in core_keygen temp1=%B ",temp);

	element_pow_zn(temp, temp, r);
	//element_printf("\n in core_keygen temp2=%B ",temp);

	element_mul(prv->d1, temp, h_y);
	//element_printf("\n in core_keygen prv->d1=%B ",prv->d1);

	/* Added by ritik aggarwal on 23 december, 2018 */
	
	for(k = 0; k < M;k++){
		element_t temp, temp1;
		element_init_G1(temp, (*pub) -> p);
		element_init_G1(temp1,(*pub) -> p);
		element_init_G1(prv -> G[k][0], (*pub) -> p);
		element_init_G1(prv -> G[k][1], (*pub) -> p);
		element_pow_zn(temp, (*pub) -> g1, msk -> u[k]); 
		element_pow_zn(temp1, (*pub) -> g1, msk -> u[M + k]);
		element_pow_zn(prv -> G[k][0], temp, r);
		element_pow_zn(prv -> G[k][1], temp1,r);
		//element_printf("\n %B	%B", prv -> G[k][0], prv -> G[k][1]);	
	}
	return prv;
}

bswabe_policy_t*
base_node( int k, char* s )
{
	bswabe_policy_t* p;

	p = (bswabe_policy_t*) malloc(sizeof(bswabe_policy_t));
	p->k = k;
	p->attr = s ? strdup(s) : 0;
	p->children = g_ptr_array_new();
	p->q = 0;

	return p;
}

/*
	TODO convert this to use a GScanner and handle quotes and / or
	escapes to allow attributes with whitespace or = signs in them
*/

bswabe_policy_t*
parse_policy_postfix( char* s )
{
	char** toks;
	char** cur_toks;
	char*  tok;
	GPtrArray* stack; /* pointers to bswabe_policy_t's */
	bswabe_policy_t* root;

	toks     = g_strsplit(s, " ", 0);
	cur_toks = toks;
	stack    = g_ptr_array_new();

	while( *cur_toks )
	{
		int i, k, n;

		tok = *(cur_toks++);

		if( !*tok )
			continue;

		if( sscanf(tok, "%dof%d", &k, &n) != 2 )
			/* push leaf token */
			g_ptr_array_add(stack, base_node(1, tok));
		else
		{
			bswabe_policy_t* node;

			/* parse "kofn" operator */

			if( k < 1 )
			{
				raise_error("error parsing \"%s\": trivially satisfied operator \"%s\"\n", s, tok);
				return 0;
			}
			else if( k > n )
			{
				raise_error("error parsing \"%s\": unsatisfiable operator \"%s\"\n", s, tok);
				return 0;
			}
			else if( n == 1 )
			{
				raise_error("error parsing \"%s\": identity operator \"%s\"\n", s, tok);
				return 0;
			}
			else if( n > stack->len )
			{
				raise_error("error parsing \"%s\": stack underflow at \"%s\"\n", s, tok);
				return 0;
			}
			
			/* pop n things and fill in children */
			node = base_node(k, 0);
			g_ptr_array_set_size(node->children, n);
			for( i = n - 1; i >= 0; i-- )
				node->children->pdata[i] = g_ptr_array_remove_index(stack, stack->len - 1);
			
			/* push result */
			g_ptr_array_add(stack, node);
		}
	}

	if( stack->len > 1 )
	{
		raise_error("error parsing \"%s\": extra tokens left on stack\n", s);
		return 0;
	}
	else if( stack->len < 1 )
	{
		raise_error("error parsing \"%s\": empty policy\n", s);
		return 0;
	}

	root = g_ptr_array_index(stack, 0);

 	g_strfreev(toks);
 	g_ptr_array_free(stack, 0);

	return root;
}

bswabe_polynomial_t*
rand_poly( int deg, element_t zero_val )
{
	int i;
	bswabe_polynomial_t* q;

	q = (bswabe_polynomial_t*) malloc(sizeof(bswabe_polynomial_t));
	q->deg = deg;
	q->coef = (element_t*) malloc(sizeof(element_t) * (deg + 1));

	for( i = 0; i < q->deg + 1; i++ )
		element_init_same_as(q->coef[i], zero_val);

	element_set(q->coef[0], zero_val);

	for( i = 1; i < q->deg + 1; i++ )
 		element_random(q->coef[i]);

	return q;
}

void
eval_poly( element_t r, bswabe_polynomial_t* q, element_t x )
{
	int i;
	element_t s, t;

	element_init_same_as(s, r);
	element_init_same_as(t, r);

	element_set0(r);
	element_set1(t);

	for( i = 0; i < q->deg + 1; i++ )
	{
		/* r += q->coef[i] * t */
		element_mul(s, q->coef[i], t);
		element_add(r, r, s);

		/* t *= x */
		element_mul(t, t, x);
	}

	element_clear(s);
	element_clear(t);
}

void
fill_policy( bswabe_policy_t* p, bswabe_pub_t* pub, element_t e )
{
	int i;
	element_t r;
	element_t t;
	element_t h;

	element_init_Zr(r, pub->p);
	element_init_Zr(t, pub->p);
	element_init_G2(h, pub->p);

	p->q = rand_poly(p->k - 1, e);

	if( p->children->len == 0 )
	{
		element_init_G1(p->c,  pub->p);
		element_init_G2(p->cp, pub->p);

		element_from_string(h, p->attr);
		element_pow_zn(p->c,  pub->g1, p->q->coef[0]);
		element_pow_zn(p->cp, h,      p->q->coef[0]);
	}
	else
		for( i = 0; i < p->children->len; i++ )
		{
			element_set_si(r, i + 1);
			eval_poly(t, p->q, r);
			fill_policy(g_ptr_array_index(p->children, i), pub, t);
		}

	element_clear(r);
	element_clear(t);
	element_clear(h);
}

bswabe_cph_t*
bswabe_enc( bswabe_pub_t* pub, element_t m, char** attrib, bswabe_verification_t** V)
{
	int M = 128;
	bswabe_cph_t* cph;
	int z;
 	element_t s;
 	element_t mult, mult2;
 	element_t sum,count,tem,tempp;
 	char temp='1';
 	int i,j,k,l,flag=0, flag2 = 0;
	int countcheck = 0;
	/* initialize */
	FILE *ptr = fopen("revoke.txt", "w");
	for(z = 1;z<= pub -> count;z++){
		fprintf(ptr, "%d\n", z);
	}
	bswabe_sigver_t* pair = sigkeygen(pub);

	cph = malloc(sizeof(bswabe_cph_t));

	element_init_Zr(s, pub->p);
	element_init_GT(m, pub->p);
	element_init_GT(tempp, pub->p);
	element_init_GT(cph->cs, pub->p);
	element_init_G1(cph->c,  pub->p);
	element_init_G1(cph->c3, pub->p);   
	element_init_G1(mult,  pub->p);
	element_init_G1(sum, pub->p);
	element_init_G1(count, pub->p);
	element_init_G1(tem, pub->p);
	element_init_G1(mult2, pub -> p);
	//element_random(mult);
	//element_random(count);
	//element_set(count,mult);
	//element_sub(mult,mult,count);
 				//element_set(mult,pub->T[i][j]);
 	//element_printf("\nFirst time mult=%B count=%B",mult,count);
	/*element_random(tem);
	element_mul(tem,count,sum);
	element_printf("\n in core_enc tem=%B",tem);*/

	//element_set1(tem);
	//element_printf("\n in core_enc tem=%B",tem);

	cph->comps_enc = g_array_new(0, 1, sizeof(bswabe_enc_comp_t));
	//cph->p = parse_policy_postfix(policy); //tree making

	
	//C1
	element_random(s);
 	element_random(m);
 	element_pow_zn(tempp, pub->Y, s);
 	//element_printf("\ntempp=%B",tempp);
 	element_mul(cph->cs, tempp, m);
 	//element_printf("\npub->Y=%B",pub->Y);
 	//element_printf("\ncph->cs=%B",cph->cs);
 	//element_printf("\nIn core_enc m=%B",m);
 	
 	//C2
 	//element_printf("\nIn core_enc s=%B",s);
 	element_pow_zn(cph->c, pub->g1, s);
 	//element_printf("\ncph->c=%B",cph->c);
 	
 	//C3
 	i=0;j=0;
 	flag=0;
	while( *attrib )
	{
		printf("\n in enc----in while \n");
		bswabe_enc_comp_t c;

		c.attr = *(attrib);
		printf("\nc.attr= [%c]",c.attr);
		//printf("\nprinting attrib");
		printf("\nattributes from orig= [%s]",*(attrib));
		//printf("\nafter printing attrib");
		//printf("\nch= [%s]",ch);
		k=strcmp(*(attrib),"1");
		//printf("\nvalue of comparison= %d",k);
		
 		if(k==0 )
 		{
 			printf("\nIn if");
 			if(flag==0)
 			{
 				//element_printf("\nFirst time befor set mult=%B pub_key=%B",mult,pub->T[i][j]);
 				element_set(mult,pub->T[i][j]);
 				//element_add(mult,mult,pub->T[i][j]);
 				//element_printf("\nFirst time mult=%B",mult);
 				flag=1;
 			}
 			else
 			{
 				element_mul(mult,mult,pub->T[i][j]);
 				//element_printf("\n in while core_enc mult=%B of pub->T[][]=%B ",mult,pub->T[i][j]);
 			}
 			
 		}
 		g_array_append_val(cph->comps_enc, c);
		j++;
		if(j%3==0)
		{
			j=0;
			i++;
		}
		*(attrib++);
	}
	/* Added by Ritik Aggarwal on 27th Decemeber */
	
	for(l = 0;l<M;l++){
		
		if(flag2 == 0){
			if(pair-> a -> y_s[l] == '0'){
				element_set(mult2, pub -> U[l]);
			}
			else{
				element_set(mult2, pub -> U[M + l]);
			}
			flag2 = 1;
			countcheck++;
		}
		else{
			if(pair -> a -> y_s[l] == '0'){
				element_mul(mult2, mult2,pub -> U[l]);
			}
			else{
				element_mul(mult2, mult2,pub -> U[M+l]);
			}
			//element_printf("\n--%d----mutl2 == %B----------",countcheck,mult2);
			countcheck++;
		}

	}
	//printf("\nHEllo");
	//element_printf("\nsum=%B",sum);
	element_mul(mult, mult,mult2);
	//printf("\nHI");
	element_pow_zn(cph->c3, mult, s);
	//printf("BYE");
	//element_printf("\ncph->c3=%B",cph->c3);
	//fill_policy(cph->p, pub, s);
	cph -> signature = malloc(sizeof(bswabe_signature_t));
	cph -> signature = sign(pair -> b,cph, pub);
	*V = malloc(sizeof(bswabe_verification_t));
	(*V) = pair -> a;
	//element_printf("verification key is %B", (*V) -> g_xy);
	return cph;
}

void
check_sat( bswabe_policy_t* p, bswabe_prv_t* prv )
{
	int i, l;

	p->satisfiable = 0;
	if( p->children->len == 0 )
	{
		for( i = 0; i < prv->comps->len; i++ )
			if( !strcmp(g_array_index(prv->comps, bswabe_prv_comp_t, i).attr,p->attr) )
			{
				p->satisfiable = 1;
				p->attri = i;
				break;
			}
	}
	else
	{
		for( i = 0; i < p->children->len; i++ )
			check_sat(g_ptr_array_index(p->children, i), prv);

		l = 0;
		for( i = 0; i < p->children->len; i++ )
			if( ((bswabe_policy_t*) g_ptr_array_index(p->children, i))->satisfiable )
				l++;

		if( l >= p->k )
			p->satisfiable = 1;
	}
}

void
pick_sat_naive( bswabe_policy_t* p, bswabe_prv_t* prv )
{
	int i, k, l;

	assert(p->satisfiable == 1);

	if( p->children->len == 0 )
		return;

	p->satl = g_array_new(0, 0, sizeof(int));

	l = 0;
	for( i = 0; i < p->children->len && l < p->k; i++ )
		if( ((bswabe_policy_t*) g_ptr_array_index(p->children, i))->satisfiable )
		{
			pick_sat_naive(g_ptr_array_index(p->children, i), prv);
			l++;
			k = i + 1;
			g_array_append_val(p->satl, k);
		}
}

/* TODO there should be a better way of doing this */
bswabe_policy_t* cur_comp_pol;
int
cmp_int( const void* a, const void* b )
{
	int k, l;
	
	k = ((bswabe_policy_t*) g_ptr_array_index(cur_comp_pol->children, *((int*)a)))->min_leaves;
	l = ((bswabe_policy_t*) g_ptr_array_index(cur_comp_pol->children, *((int*)b)))->min_leaves;

	return
		k <  l ? -1 :
		k == l ?  0 : 1;
}

void
pick_sat_min_leaves( bswabe_policy_t* p, bswabe_prv_t* prv )
{
	int i, k, l;
	int* c;

	assert(p->satisfiable == 1);

	if( p->children->len == 0 )
		p->min_leaves = 1;
	else
	{
		for( i = 0; i < p->children->len; i++ )
			if( ((bswabe_policy_t*) g_ptr_array_index(p->children, i))->satisfiable )
				pick_sat_min_leaves(g_ptr_array_index(p->children, i), prv);

		c = alloca(sizeof(int) * p->children->len);
		for( i = 0; i < p->children->len; i++ )
			c[i] = i;

		cur_comp_pol = p;
		qsort(c, p->children->len, sizeof(int), cmp_int);

		p->satl = g_array_new(0, 0, sizeof(int));
		p->min_leaves = 0;
		l = 0;

		for( i = 0; i < p->children->len && l < p->k; i++ )
			if( ((bswabe_policy_t*) g_ptr_array_index(p->children, c[i]))->satisfiable )
			{
				l++;
				p->min_leaves += ((bswabe_policy_t*) g_ptr_array_index(p->children, c[i]))->min_leaves;
				k = c[i] + 1;
				g_array_append_val(p->satl, k);
			}
		assert(l == p->k);
	}
}

void
lagrange_coef( element_t r, GArray* s, int i )
{
	int j, k;
	element_t t;

	element_init_same_as(t, r);

	element_set1(r);
	for( k = 0; k < s->len; k++ )
	{
		j = g_array_index(s, int, k);
		if( j == i )
			continue;
		element_set_si(t, - j);
		element_mul(r, r, t); /* num_muls++; */
		element_set_si(t, i - j);
		element_invert(t, t);
		element_mul(r, r, t); /* num_muls++; */
	}

	element_clear(t);
}

void
dec_leaf_naive( element_t r, bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub )
{
	bswabe_prv_comp_t* c;
	element_t s;

	c = &(g_array_index(prv->comps, bswabe_prv_comp_t, p->attri));

	element_init_GT(s, pub->p);

	pairing_apply(r, p->c,  c->d,  pub->p); /* num_pairings++; */
	pairing_apply(s, p->cp, c->dp, pub->p); /* num_pairings++; */
	element_invert(s, s);
	element_mul(r, r, s); /* num_muls++; */

	element_clear(s);
}

void dec_node_naive( element_t r, bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub );

void
dec_internal_naive( element_t r, bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub )
{
	int i;
	element_t s;
	element_t t;

	element_init_GT(s, pub->p);
	element_init_Zr(t, pub->p);

	element_set1(r);
	for( i = 0; i < p->satl->len; i++ )
	{
		dec_node_naive
			(s, g_ptr_array_index
			 (p->children, g_array_index(p->satl, int, i) - 1), prv, pub);
 		lagrange_coef(t, p->satl, g_array_index(p->satl, int, i));
		element_pow_zn(s, s, t); /* num_exps++; */
		element_mul(r, r, s); /* num_muls++; */
	}

	element_clear(s);
	element_clear(t);
}

void
dec_node_naive( element_t r, bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub )
{
	assert(p->satisfiable);
	if( p->children->len == 0 )
		dec_leaf_naive(r, p, prv, pub);
	else
		dec_internal_naive(r, p, prv, pub);
}

void
dec_naive( element_t r, bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub )
{
	dec_node_naive(r, p, prv, pub);
}

void
dec_leaf_merge( element_t exp, bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub )
{
	bswabe_prv_comp_t* c;
	element_t s;

	c = &(g_array_index(prv->comps, bswabe_prv_comp_t, p->attri));

	if( !c->used )
	{
		c->used = 1;
		element_init_G1(c->z,  pub->p);
		element_init_G1(c->zp, pub->p);
		element_set1(c->z);
		element_set1(c->zp);
	}

	element_init_G1(s, pub->p);

	element_pow_zn(s, p->c, exp); /* num_exps++; */
	element_mul(c->z, c->z, s); /* num_muls++; */

	element_pow_zn(s, p->cp, exp); /* num_exps++; */
	element_mul(c->zp, c->zp, s); /* num_muls++; */

	element_clear(s);
}

void dec_node_merge( element_t exp, bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub );

void
dec_internal_merge( element_t exp, bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub )
{
	int i;
	element_t t;
	element_t expnew;

	element_init_Zr(t, pub->p);
	element_init_Zr(expnew, pub->p);

	for( i = 0; i < p->satl->len; i++ )
	{
 		lagrange_coef(t, p->satl, g_array_index(p->satl, int, i));
		element_mul(expnew, exp, t); /* num_muls++; */
		dec_node_merge(expnew, g_ptr_array_index
									 (p->children, g_array_index(p->satl, int, i) - 1), prv, pub);
	}

	element_clear(t);
	element_clear(expnew);
}

void
dec_node_merge( element_t exp, bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub )
{
	assert(p->satisfiable);
	if( p->children->len == 0 )
		dec_leaf_merge(exp, p, prv, pub);
	else
		dec_internal_merge(exp, p, prv, pub);
}

void
dec_merge( element_t r, bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub )
{
	int i;
	element_t one;
	element_t s;

	/* first mark all attributes as unused */
	for( i = 0; i < prv->comps->len; i++ )
		g_array_index(prv->comps, bswabe_prv_comp_t, i).used = 0;

	/* now fill in the z's and zp's */
	element_init_Zr(one, pub->p);
	element_set1(one);
	dec_node_merge(one, p, prv, pub);
	element_clear(one);

	/* now do all the pairings and multiply everything together */
	element_set1(r);
	element_init_GT(s, pub->p);
	for( i = 0; i < prv->comps->len; i++ )
		if( g_array_index(prv->comps, bswabe_prv_comp_t, i).used )
		{
			bswabe_prv_comp_t* c = &(g_array_index(prv->comps, bswabe_prv_comp_t, i));

			pairing_apply(s, c->z, c->d, pub->p); /* num_pairings++; */
			element_mul(r, r, s); /* num_muls++; */

			pairing_apply(s, c->zp, c->dp, pub->p); /* num_pairings++; */
			element_invert(s, s);
			element_mul(r, r, s); /* num_muls++; */
		}
	element_clear(s);
}

void
dec_leaf_flatten( element_t r, element_t exp,
									bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub )
{
	bswabe_prv_comp_t* c;
	element_t s;
	element_t t;

	c = &(g_array_index(prv->comps, bswabe_prv_comp_t, p->attri));

	element_init_GT(s, pub->p);
	element_init_GT(t, pub->p);

	pairing_apply(s, p->c,  c->d,  pub->p); /* num_pairings++; */
	pairing_apply(t, p->cp, c->dp, pub->p); /* num_pairings++; */
	element_invert(t, t);
	element_mul(s, s, t); /* num_muls++; */
	element_pow_zn(s, s, exp); /* num_exps++; */

	element_mul(r, r, s); /* num_muls++; */

	element_clear(s);
	element_clear(t);
}

void dec_node_flatten( element_t r, element_t exp,
											 bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub );

void
dec_internal_flatten( element_t r, element_t exp,
											bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub )
{
	int i;
	element_t t;
	element_t expnew;

	element_init_Zr(t, pub->p);
	element_init_Zr(expnew, pub->p);

	for( i = 0; i < p->satl->len; i++ )
	{
 		lagrange_coef(t, p->satl, g_array_index(p->satl, int, i));
		element_mul(expnew, exp, t); /* num_muls++; */
		dec_node_flatten(r, expnew, g_ptr_array_index
										 (p->children, g_array_index(p->satl, int, i) - 1), prv, pub);
	}

	element_clear(t);
	element_clear(expnew);
}

void
dec_node_flatten( element_t r, element_t exp,
									bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub )
{
	assert(p->satisfiable);
	if( p->children->len == 0 )
		dec_leaf_flatten(r, exp, p, prv, pub);
	else
		dec_internal_flatten(r, exp, p, prv, pub);
}

void
dec_flatten( element_t r, bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub )
{
	element_t one;

	element_init_Zr(one, pub->p);

	element_set1(one);
	element_set1(r);

	dec_node_flatten(r, one, p, prv, pub);

	element_clear(one);
}

bswabe_proxy_t* bswabe_proxy(bswabe_prv_t* prv,bswabe_msk_t* msk,bswabe_pub_t* pub,bswabe_cph_t* cph)
{
	bswabe_proxy_t* pxy;
	element_t sum,ga,ga1,ga2,te;
	int flagy=0,num,i,ans,temp,tempp;///
	int flag = 0;
	int count = 0;
	FILE *ptr;
	int number = (pub->total_attr) * 3;
	int flagggy = 0;
	int prev_number = -1;
	int curr_id;
	pxy = malloc(sizeof(bswabe_proxy_t));
	int revocation_list[number];
	memset(revocation_list, -1 ,  number * sizeof(int));

	element_init_G1(pxy->Cuser, pub->p);
	element_init_G1(pxy->Cattr, pub->p); ////here Cattr=a///
	element_init_G1(te, pub->p);
	//element_init_Zr(pxy->flag, pub->p);
	element_init_Zr(sum, pub->p);
	element_init_Zr(ga , pub->p);
	element_init_Zr(ga1, pub->p);
	element_init_Zr(ga2, pub->p);

	printf("\n Want to revoke :::  User:2 Attribute:1  No revocation:0  ");
	scanf("%d",&ans);
	if(ans == 2){
		printf("\n you are revoked cannot decrypt");
	}
	if(ans)
	{
		pxy->on = 1;
		printf("----%d",pxy->on);

	    ptr = fopen("revoke.txt","r");
	    if (ptr== NULL)
	    {
		    printf("can not open file \n");
		    return 1;
	    }
		while(1)
		{
			fscanf(ptr,"%d",&curr_id);
			if(curr_id == -2){
				break;
			}
			if(prev_number == -1 && curr_id == prv -> id){
				break;
			}
			prev_number = curr_id;
		}
			//if(temp== -2)
		    	//break;
			//printf("\nEnter the attribute number to be removed:: ");
			//scanf("%d%d",&row,&col);
			//fscanf(ptr,"%d",&temp);
		while(curr_id != -1){
		    fscanf(ptr, "%d", &curr_id);
		    int row = curr_id / 3;
		    int col = curr_id % 3;
		    //printf("\n%d", temp);
		    //row= temp;

		    //fscanf(ptr,"%d",&tempp);
		    //printf("\n%d", tempp);
		    //col=tempp;
			//int z = row * 3 + col;
			revocation_list[count] = curr_id;
			count++;
			element_add(sum,sum,msk->t[row][col]);
			
		}

		for(i=0;i<number;i++)
		{
		int j = 0;
		printf("\nAttribute of user = %s ",g_array_index(prv->comps, bswabe_prv_comp_t, i).attr);
		printf("\nAttribute of scheme= %s",g_array_index(cph->comps_enc, bswabe_enc_comp_t, i).attr);
		flagggy = 0;
		while(revocation_list[j] != -1){
			if(i == revocation_list[j]){
				flagggy = 1;
			}
			j++;

		}

		if(flagggy != 1){
		if((strcmp(g_array_index(prv->comps, bswabe_prv_comp_t, i).attr,g_array_index(cph->comps_enc, bswabe_enc_comp_t, i).attr)!=0)){
			flag=1;
			break;
			}
		}
		}
		if(flag == 1){
			printf("Cannot decrypt");
			return NULL;
		}
		/*element_random(ga);
		element_pow_zn(pxy->Cuser, prv->d, ga);

		element_pow_zn(te, prv->d, ga);
		element_pow_zn(te, te, sum);
		element_invert(te,te);
		element_pow_zn(pxy->Cattr, prv->d1, ga);
		element_mul(pxy->Cattr, pxy->Cattr, te );
		element_printf("\nIn proxy\nCuser = %B \n Cattr= %B",pxy->Cuser,pxy->Cattr);*/
		//element_pow_zn(pxy->Cuser, prv->d, gamma);
		element_random(pxy->Cuser);
		element_pow_zn(pxy->Cuser, pxy->Cuser, ga);
		element_pow_zn(te, prv->d, sum);
		element_invert(te,te);
		element_mul(pxy->Cattr, prv->d1, te );
		element_mul(pxy->Cattr, pxy->Cattr, pxy->Cuser );
		//element_printf("\nIn proxy\nCuser = %B \n Cattr= %B",pxy->Cuser,pxy->Cattr);
		fclose(ptr);
	}
	else
	{
		pxy->on= 0;
		
		for(i=0;i<number;i++)
		{

		printf("\nAttribute of user = %s ",g_array_index(prv->comps, bswabe_prv_comp_t, i).attr);
		printf("\nAttribute of scheme= %s",g_array_index(cph->comps_enc, bswabe_enc_comp_t, i).attr);
		if(strcmp(g_array_index(prv->comps, bswabe_prv_comp_t, i).attr,g_array_index(cph->comps_enc, bswabe_enc_comp_t, i).attr)!=0){
			flag=1;
			break;
			}
		}
		if(flag == 1){
			printf("cannot decrypt");
			return NULL;
		}
		/*element_random(ga);
		element_pow_zn(pxy->Cuser, prv->d, ga);
		element_pow_zn(pxy->Cattr, prv->d1, ga);
		element_printf("\nIn proxy\nCuser = %B \n Cattr= %B",pxy->Cuser,pxy->Cattr);*/
		//actual code
		element_random(pxy->Cuser);
		//element_printf("\n----%B-----", pxy -> Cuser);
		element_pow_zn(pxy->Cuser, pxy->Cuser, ga);
		element_mul(pxy->Cattr, prv->d1, pxy->Cuser);		
		//element_printf("\nIn proxy\nCuser = %B \n a= %B",pxy->Cuser,pxy->Cattr);
	}

	return pxy;

}


int
bswabe_dec( bswabe_pub_t* pub, bswabe_prv_t* prv, bswabe_cph_t* cph, bswabe_msk_t* msk, element_t m,bswabe_verification_t* V)
{	

	if(verify(V, cph -> signature , cph, pub) == 1){
	bswabe_proxy_t* pxyy;

	element_t t,t1,user_ele,pi;
	char bv;
	int i=0,j=0,flag,number,count=1,M=128;

	//bswabe_enc_comp_t c1;
	//bswabe_prv_comp_t c2;
	//PROXY CALL
	element_init_G1(user_ele, pub->p);
	pxyy = bswabe_proxy(prv, msk, pub,cph);

	if(pxyy == NULL){
		return 0;
	}
	//element_printf("\nIn Dec\nUser element Cattr= %B", pxyy->Cattr);
	//element_printf("\nUser element Cuser= %B", pxyy->Cuser);
	//printf("\n Flag value: = %d",pxyy->on);
	//END

	element_init_GT(m, pub->p);
	element_init_GT(t, pub->p);
	element_init_GT(t1, pub->p);
	element_init_G1(pi, pub -> p);
	element_set1(pi);
	
	//printf("\nIn core_dec");

	/*element_printf("g1 = %B\n", (pub)->g1);
  	element_printf("h = %B\n", (pub)->h);
  	element_printf("Y = %B\n", (pub)->Y);
  	for(i=0;i<3;i++)
  		for(j=0;j<3;j++)
  			element_printf("\npub->T[%d][%d]= %B",i,j,(pub)->T[i][j]);*/
  	//printf("\nAfter printing pub_key");
  	//element_printf("\nd1 = %B\n", prv->d1);
  	//element_printf("d = %B\n", prv->d);
  	//printf("\nAfter printing prv_key");
	//check_sat(cph->p, prv);
	
	//printf("\nAfter printing prv_key");
	//element_printf("\ncs=%B",cph->cs);
	//element_printf("\nc=%B",cph->c);
	//element_printf("\nc3=%B",cph->c3);
	//printf("\nAfter printing enc_key");
	/*if( flag )
	{
		raise_error("cannot decrypt, attributes in key do not satisfy policy\n");
		return 0;
	}*/
		/*
		//multiplying d1 with Cuser
		element_mul(prv->d1, prv->d1, pxyy->Cattr);
		pairing_apply(t, cph->c3, prv->d, pub->p);
		element_printf("\nAfter pairing_apply t=%B",t);
		
		element_mul(m, cph->cs, t);
		element_printf("\nAfter ele_mul m=%B",m);
		
		pairing_apply(t1, cph->c, prv->d1, pub->p);
		element_printf("\nAfter pairing_apply t1=%B",t1);
		
		element_invert(t1, t1);
		element_printf("\nAfter invert t1=%B",t1);
		
		element_mul(m, m, t1);
		element_printf("\nIn core_dec m=%B",m);*/
	
		//Actual code
		//changing Cuser by dividing it with a

		//Calculating pi to be multipied

		/* Added by Sanskriti */
		for(count=1;count<M;count++){
			bv=V->y_s[count];
			if(bv=='0')
				element_mul(pi, pi,prv -> G[count][0]);
			else if (bv=='1')
				element_mul(pi, pi,prv -> G[count][1]);
		}

		element_invert(pxyy->Cuser,pxyy->Cuser);
		element_mul(pxyy->Cattr, pxyy->Cattr, pxyy->Cuser);
		//element_printf("\nCattr after multiplying by Cuser = %B",pxyy->Cattr);

		pairing_apply(t, cph->c3, prv->d, pub->p);
		//pairing_apply(t, cph->c3, pxyy->Cuser, pub->p);
		//element_printf("\nAfter pairing_apply t=%B",t);
		
		element_mul(m, cph->cs, t);
		//element_printf("\nAfter ele_mul m=%B",m);
		
		element_mul(pxyy->Cattr, pxyy->Cattr, pi);
		
		pairing_apply(t1, cph->c, pxyy->Cattr, pub->p);
		//element_printf("\nAfter pairing_apply t1=%B",t1);
		
		element_invert(t1, t1);
		//element_printf("\nAfter invert t1=%B",t1);
		
		element_mul(m, m, t1);
		//element_printf("\nIn core_dec m=%B",m);

	
	
/* 	if( no_opt_sat ) */
/* 		pick_sat_naive(cph->p, prv); */
/* 	else */
	//zeya pick_sat_min_leaves(cph->p, prv);

/* 	if( dec_strategy == DEC_NAIVE ) */
/* 		dec_naive(t, cph->p, prv, pub); */
/* 	else if( dec_strategy == DEC_FLATTEN ) */
	//zeya dec_flatten(t, cph->p, prv, pub);
/* 	else */
/* 		dec_merge(t, cph->p, prv, pub); */

	//zeya element_mul(m, cph->cs, t); /* num_muls++; */

	//zeya pairing_apply(t, cph->c, prv->d, pub->p); /* num_pairings++; */
	//zeya element_invert(t, t);
	//zeya element_mul(m, m, t); /* num_muls++; */

	return 1;
	}
	else{
		return 0;
	}
}
