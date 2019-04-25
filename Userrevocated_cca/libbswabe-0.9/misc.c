#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <pbc.h>

#include "bswabe.h"
#include "private.h"


void
serialize_uint32( GByteArray* b, uint32_t k )
{
	int i;
	guint8 byte;

	for( i = 3; i >= 0; i-- )
	{
		byte = (k & 0xff<<(i*8))>>(i*8);
		g_byte_array_append(b, &byte, 1);
	}
}

uint32_t
unserialize_uint32( GByteArray* b, int* offset )
{
	int i;
	uint32_t r;

	r = 0;
	for( i = 3; i >= 0; i-- )
		r |= (b->data[(*offset)++])<<(i*8);

	return r;
}

void
serialize_element( GByteArray* b, element_t e )
{
	uint32_t len;
	unsigned char* buf;

	len = element_length_in_bytes(e);
	serialize_uint32(b, len);

	buf = (unsigned char*) malloc(len);
	element_to_bytes(buf, e);
	g_byte_array_append(b, buf, len);
	free(buf);
}

void
unserialize_element( GByteArray* b, int* offset, element_t e )
{
	uint32_t len;
	unsigned char* buf;

	len = unserialize_uint32(b, offset);

	buf = (unsigned char*) malloc(len);
	memcpy(buf, b->data + *offset, len);
	*offset += len;

	element_from_bytes(e, buf);
	free(buf);
}

void
serialize_string( GByteArray* b, char* s )
{
	g_byte_array_append(b, (unsigned char*) s, strlen(s) + 1);
}

char*
unserialize_string( GByteArray* b, int* offset )
{
	GString* s;
	char* r;
	char c;

	s = g_string_sized_new(32);
	while( 1 )
	{
		c = b->data[(*offset)++];
		if( c && c != EOF )
			g_string_append_c(s, c);
		else
			break;
	}

	r = s->str;
	g_string_free(s, 0);

	return r;
}

GByteArray*
bswabe_pub_serialize( bswabe_pub_t* pub )		///
{
	GByteArray* b;
	int i,j,temp;
	temp= (pub->total_attr);
	b = g_byte_array_new();
	serialize_string(b,  pub->pairing_desc);
	serialize_uint32(b,  pub->total_attr);
	serialize_element(b, pub->g1);
	serialize_element(b, pub->h);
	serialize_element(b, pub->Y);
	for(i=0;i<temp;i++)
		for(j=0;j<3;j++)
			serialize_element(b, pub->T[i][j]);
	for(i=0;i<256;i++)
		serialize_element(b,pub->U[i]);	
	serialize_uint32(b, pub -> count);			
	return b;
}

bswabe_pub_t*
bswabe_pub_unserialize( GByteArray* b, int free )
{
	bswabe_pub_t* pub;
	int offset,i,j;

	pub = (bswabe_pub_t*) malloc(sizeof(bswabe_pub_t));
	offset = 0;

	pub->pairing_desc = unserialize_string(b, &offset);
	pairing_init_set_buf(pub->p, pub->pairing_desc, strlen(pub->pairing_desc));
	pub->total_attr = (int) unserialize_uint32(b, &offset);
	printf("\nfrom unserialize = %d ", (pub->total_attr));
	element_init_G1(pub->g1,           pub->p);
	element_init_G1(pub->h,           pub->p);
	element_init_GT(pub->Y,          pub->p);
	for(i=0;i<(pub->total_attr);i++)
		for(j=0;j<3;j++)
			element_init_G1(pub->T[i][j], pub->p);
	for(i=0;i<256;i++)
		element_init_G1(pub->U[i],pub->p);
	unserialize_element(b, &offset, pub->g1);
	unserialize_element(b, &offset, pub->h);
	unserialize_element(b, &offset, pub->Y);
	for(i=0;i<(pub->total_attr);i++)
		for(j=0;j<3;j++)
			unserialize_element(b, &offset, pub->T[i][j]);
	for(i=0;i<256;i++)
		unserialize_element(b,&offset,pub->U[i]);
	pub -> count = unserialize_uint32(b, &offset);
	if( free )
		g_byte_array_free(b, 1);

	return pub;
}

GByteArray*
bswabe_msk_serialize( bswabe_msk_t* msk ,int n)
{
	GByteArray* b;
	int i,j;
	b = g_byte_array_new();
	serialize_element(b, msk->y);
	for(i=0;i<n;i++)
		for(j=0;j<3;j++)
			serialize_element(b, msk->t[i][j]);
	for(i=0;i<256;i++)
		serialize_element(b,msk->u[i]);
	return b;
}

bswabe_msk_t*
bswabe_msk_unserialize( bswabe_pub_t* pub, GByteArray* b, int free )
{
	bswabe_msk_t* msk;
	int offset,i,j;

	msk = (bswabe_msk_t*) malloc(sizeof(bswabe_msk_t));
	offset = 0;

	element_init_Zr(msk->y, pub->p);
	for(i=0;i<(pub->total_attr);i++)
		for(j=0;j<3;j++)
			element_init_Zr(msk->t[i][j], pub->p);
	for(i=0;i<256;i++)
		element_init_Zr(msk->u[i],pub->p);
	printf("\nIn msk_unseri 1");
	unserialize_element(b, &offset, msk->y);
	for(i=0;i<(pub->total_attr);i++)
		for(j=0;j<3;j++)
			unserialize_element(b, &offset, msk->t[i][j]);
	for(i=0;i<256;i++)
		unserialize_element(b,&offset,msk->u[i]);
	printf("\nIn msk_unseri 2");
	if( free )
		g_byte_array_free(b, 1);

	return msk;
}

GByteArray*
bswabe_prv_serialize( bswabe_prv_t* prv )
{
	GByteArray* b;
	int i,j;

	b = g_byte_array_new();

	serialize_element(b, prv->d);
	serialize_element(b, prv->d1);
	serialize_uint32( b, prv->comps->len);
	
	for( i = 0; i < prv->comps->len; i++ )
	{
		serialize_string( b, g_array_index(prv->comps, bswabe_prv_comp_t, i).attr);
		serialize_element(b, g_array_index(prv->comps, bswabe_prv_comp_t, i).d);
		serialize_element(b, g_array_index(prv->comps, bswabe_prv_comp_t, i).dp);
	}
	for(i=0;i<128;i++){
		for(j=0;j<2;j++)
			serialize_element(b,prv->G[i][j]);
	}
	serialize_uint32(b, prv -> id);
	return b;
}

bswabe_prv_t*
bswabe_prv_unserialize( bswabe_pub_t* pub, GByteArray* b, int free )
{
	bswabe_prv_t* prv;
	int i,j;
	int len;
	int offset;

	prv = (bswabe_prv_t*) malloc(sizeof(bswabe_prv_t));
	offset = 0;

	element_init_G1(prv->d, pub->p);
	unserialize_element(b, &offset, prv->d);
	element_init_G1(prv->d1, pub->p);
	unserialize_element(b, &offset, prv->d1);
	
	prv->comps = g_array_new(0, 1, sizeof(bswabe_prv_comp_t));
	len = unserialize_uint32(b, &offset);

	for( i = 0; i < len; i++ )
	{
		bswabe_prv_comp_t c;

		c.attr = unserialize_string(b, &offset);


		element_init_G2(c.d,  pub->p);
		element_init_G2(c.dp, pub->p);

		unserialize_element(b, &offset, c.d);
		unserialize_element(b, &offset, c.dp);

		g_array_append_val(prv->comps, c);
	}

	for(i=0;i<128;i++){
		for(j=0;j<2;j++){
			element_init_G1(prv->G[i][j],pub->p);
			unserialize_element(b,&offset,prv->G[i][j]);
		}
	}
	prv -> id = unserialize_uint32(b, &offset);
	if( free )
		g_byte_array_free(b, 1);

	return prv;
}

void
serialize_policy( GByteArray* b, bswabe_policy_t* p )
{
	int i;

	serialize_uint32(b, (uint32_t) p->k);

	serialize_uint32(b, (uint32_t) p->children->len);
	if( p->children->len == 0 )
	{
		serialize_string( b, p->attr);
		serialize_element(b, p->c);
		serialize_element(b, p->cp);
	}
	else
		for( i = 0; i < p->children->len; i++ )
			serialize_policy(b, g_ptr_array_index(p->children, i));
}

bswabe_policy_t*
unserialize_policy( bswabe_pub_t* pub, GByteArray* b, int* offset )
{
	int i;
	int n;
	bswabe_policy_t* p;

	p = (bswabe_policy_t*) malloc(sizeof(bswabe_policy_t));

	p->k = (int) unserialize_uint32(b, offset);
	p->attr = 0;
	p->children = g_ptr_array_new();

	n = unserialize_uint32(b, offset);
	if( n == 0 )
	{
		p->attr = unserialize_string(b, offset);
		element_init_G1(p->c,  pub->p);
		element_init_G1(p->cp, pub->p);
		unserialize_element(b, offset, p->c);
		unserialize_element(b, offset, p->cp);
	}
	else
		for( i = 0; i < n; i++ )
			g_ptr_array_add(p->children, unserialize_policy(pub, b, offset));

	return p;
}

GByteArray*
bswabe_cph_serialize( bswabe_cph_t* cph )
{
	GByteArray* b;
	int i;

	b = g_byte_array_new();
	serialize_element(b, cph->cs);
	serialize_element(b, cph->c);
	serialize_element(b, cph->c3);
	//here
	
	//^^
	serialize_uint32( b, cph->comps_enc->len);

	for( i = 0; i < cph->comps_enc->len; i++ )
	{
		serialize_string( b, g_array_index(cph->comps_enc, bswabe_enc_comp_t, i).attr);
	}
	//serialize_policy( b, cph->p);

	serialize_element(b, cph -> signature -> sigma);

	return b;
}

bswabe_cph_t*
bswabe_cph_unserialize( bswabe_pub_t* pub, GByteArray* b, int free )
{
	bswabe_cph_t* cph;
	int offset,i,len;

	cph = (bswabe_cph_t*) malloc(sizeof(bswabe_cph_t));
	offset = 0;
	
	element_init_GT(cph->cs, pub->p);
	element_init_G1(cph->c,  pub->p);
	element_init_G1(cph->c3,  pub->p);  
	unserialize_element(b, &offset, cph->cs);
	unserialize_element(b, &offset, cph->c);
	unserialize_element(b, &offset, cph->c3);
	//here
	
	//^^
	//cph->p = unserialize_policy(pub, b, &offset);

	cph->comps_enc = g_array_new(0, 1, sizeof(bswabe_enc_comp_t));
	len = unserialize_uint32(b, &offset);

	for( i = 0; i < len; i++ )
	{
		bswabe_enc_comp_t c;

		c.attr = unserialize_string(b, &offset);
		g_array_append_val(cph->comps_enc, c);
	}
	cph -> signature = malloc(sizeof(bswabe_signature_t));
	element_init_G1(cph -> signature -> sigma,pub->p);
	unserialize_element(b,&offset,cph -> signature -> sigma);

	if( free )
		g_byte_array_free(b, 1);

	return cph;
}

void
bswabe_pub_free( bswabe_pub_t* pub )
{
	int i,j;
	element_clear(pub->g1);
	element_clear(pub->h);
	element_clear(pub->Y);
	for(i = 0;i<256;i++){
		element_clear(pub -> U[i]);
	}
	for(i=0;i<(pub->total_attr);i++)
		for(j=0;j<3;j++)
			element_clear(pub->T[i][j]);
	pairing_clear(pub->p);
	free(pub->pairing_desc);
	free(pub);
}

void
bswabe_msk_free( bswabe_msk_t* msk )
{
	int i,j;
	element_clear(msk->y);
	for(i=0;i<3;i++)
		for(j=0;j<3;j++)
			element_clear(msk->t[i][j]);
	for(i = 0;i<256;i++){
		element_clear(msk -> u[i]);
	}
	free(msk);
}

void
bswabe_prv_free( bswabe_prv_t* prv )
{
	int i,j;
	
	element_clear(prv->d);

	for( i = 0; i < prv->comps->len; i++ )
	{
		bswabe_prv_comp_t c;

		c = g_array_index(prv->comps, bswabe_prv_comp_t, i);
		free(c.attr);
		element_clear(c.d);
		element_clear(c.dp);
	}
	
	for(i = 0;i<128;i++){
		for(j = 0;j<2;j++){
			element_clear(prv -> G[i][j]);
		}
	}

	g_array_free(prv->comps, 1);

	free(prv);
}

void
bswabe_policy_free( bswabe_policy_t* p )
{
	int i;

	if( p->attr )
	{
		free(p->attr);
		element_clear(p->c);
		element_clear(p->cp);
	}

	for( i = 0; i < p->children->len; i++ )
		bswabe_policy_free(g_ptr_array_index(p->children, i));

	g_ptr_array_free(p->children, 1);

	free(p);
}

void
bswabe_cph_free( bswabe_cph_t* cph )
{
	element_clear(cph->cs);
	element_clear(cph->c);
	element_clear(cph->c3);
	element_clear(cph -> signature -> sigma);
	free(cph -> signature);
	//bswabe_policy_free(cph->p);
	
}

GByteArray*
bswabe_verification_serialize( bswabe_verification_t * ver )
{
	GByteArray* b;
	int i;

	b = g_byte_array_new();

	serialize_element(b, ver->y);
	serialize_element(b, ver->g);
	serialize_element(b, ver->g_y);
	serialize_element(b, ver->g_xy);
	serialize_string(b,ver->y_s);

	return b;
}

bswabe_verification_t*
bswabe_verification_unserialize( bswabe_pub_t* pub, GByteArray* b, int free )
{
	bswabe_verification_t* ver;
	int offset,i,j;

	ver = (bswabe_verification_t*) malloc(sizeof(bswabe_verification_t));
	offset = 0;

	element_init_Zr(ver->y, pub->p);
	element_init_G2(ver->g, pub->p);
	element_init_G2(ver->g_y, pub->p);
	element_init_G2(ver->g_xy, pub->p);

	



	printf("\nIn ver_unseri");
	unserialize_element(b, &offset, ver->y);
	unserialize_element(b, &offset, ver->g);
	unserialize_element(b, &offset, ver->g_y);
	unserialize_element(b, &offset, ver->g_xy);
	ver->y_s=unserialize_string(b,&offset);

	if( free )
		g_byte_array_free(b, 1);

	return ver;
}


