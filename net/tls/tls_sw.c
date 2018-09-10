/*
 * Copyright (c) 2016-2017, Mellanox Technologies. All rights reserved.
 * Copyright (c) 2016-2017, Dave Watson <davejwatson@fb.com>. All rights reserved.
 * Copyright (c) 2016-2017, Lance Chao <lancerchao@fb.com>. All rights reserved.
 * Copyright (c) 2016, Fridolin Pokorny <fridolin.pokorny@gmail.com>. All rights reserved.
 * Copyright (c) 2016, Nikos Mavrogiannopoulos <nmav@gnutls.org>. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <linux/sched/signal.h>
#include <linux/module.h>
#include <crypto/aead.h>

#include <net/strparser.h>
#include <net/tls.h>

#define MAX_IV_SIZE	TLS_CIPHER_AES_GCM_128_IV_SIZE

static int __skb_nsg(struct sk_buff *skb, int offset, int len,
                     unsigned int recursion_level)
{
        int start = skb_headlen(skb);
        int i, chunk = start - offset;
        struct sk_buff *frag_iter;
        int elt = 0;

        if (unlikely(recursion_level >= 24))
                return -EMSGSIZE;

        if (chunk > 0) {
                if (chunk > len)
                        chunk = len;
                elt++;
                len -= chunk;
                if (len == 0)
                        return elt;
                offset += chunk;
        }

        for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
                int end;

                WARN_ON(start > offset + len);

                end = start + skb_frag_size(&skb_shinfo(skb)->frags[i]);
                chunk = end - offset;
                if (chunk > 0) {
                        if (chunk > len)
                                chunk = len;
                        elt++;
                        len -= chunk;
                        if (len == 0)
                                return elt;
                        offset += chunk;
                }
                start = end;
        }

        if (unlikely(skb_has_frag_list(skb))) {
                skb_walk_frags(skb, frag_iter) {
                        int end, ret;

                        WARN_ON(start > offset + len);

                        end = start + frag_iter->len;
                        chunk = end - offset;
                        if (chunk > 0) {
                                if (chunk > len)
                                        chunk = len;
                                ret = __skb_nsg(frag_iter, offset - start, chunk,
                                                recursion_level + 1);
                                if (unlikely(ret < 0))
                                        return ret;
                                elt += ret;
                                len -= chunk;
                                if (len == 0)
                                        return elt;
                                offset += chunk;
                        }
                        start = end;
                }
        }
        BUG_ON(len);
        return elt;
}

/* Return the number of scatterlist elements required to completely map the
 * skb, or -EMSGSIZE if the recursion depth is exceeded.
 */
static int skb_nsg(struct sk_buff *skb, int offset, int len)
{
        return __skb_nsg(skb, offset, len, 0);
}

static void tls_decrypt_done(struct crypto_async_request *req, int err)
{
	struct aead_request *aead_req = (struct aead_request *)req;
	struct scatterlist *sgout = aead_req->dst;
	struct tls_sw_context_rx *ctx;
	struct tls_context *tls_ctx;
	struct scatterlist *sg;
	struct sk_buff *skb;
	unsigned int pages;
	int pending;

	skb = (struct sk_buff *)req->data;
	tls_ctx = tls_get_ctx(skb->sk);
	ctx = tls_sw_ctx_rx(tls_ctx);
	pending = atomic_dec_return(&ctx->decrypt_pending);

	/* Propagate if there was an err */
	if (err) {
		ctx->async_wait.err = err;
		tls_err_abort(skb->sk, err);
	}

	/* After using skb->sk to propagate sk through crypto async callback
	 * we need to NULL it again.
	 */
	skb->sk = NULL;

	/* Release the skb, pages and memory allocated for crypto req */
	kfree_skb(skb);

	/* Skip the first S/G entry as it points to AAD */
	for_each_sg(sg_next(sgout), sg, UINT_MAX, pages) {
		if (!sg)
			break;
		put_page(sg_page(sg));
	}

	kfree(aead_req);

	if (!pending && READ_ONCE(ctx->async_notify))
		complete(&ctx->async_wait.completion);
}

static int tls_do_decryption(struct sock *sk,
			     struct sk_buff *skb,
			     struct scatterlist *sgin,
			     struct scatterlist *sgout,
			     char *iv_recv,
			     size_t data_len,
			     struct aead_request *aead_req,
			     bool async)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context_rx *ctx = tls_sw_ctx_rx(tls_ctx);
	int ret;

	aead_request_set_tfm(aead_req, ctx->aead_recv);
	aead_request_set_ad(aead_req, TLS_AAD_SPACE_SIZE);
	aead_request_set_crypt(aead_req, sgin, sgout,
			       data_len + tls_ctx->rx.tag_size,
			       (u8 *)iv_recv);

	if (async) {
		/* Using skb->sk to push sk through to crypto async callback
		 * handler. This allows propagating errors up to the socket
		 * if needed. It _must_ be cleared in the async handler
		 * before kfree_skb is called. We _know_ skb->sk is NULL
		 * because it is a clone from strparser.
		 */
		skb->sk = sk;
		aead_request_set_callback(aead_req,
					  CRYPTO_TFM_REQ_MAY_BACKLOG,
					  tls_decrypt_done, skb);
		atomic_inc(&ctx->decrypt_pending);
	} else {
		aead_request_set_callback(aead_req,
					  CRYPTO_TFM_REQ_MAY_BACKLOG,
					  crypto_req_done, &ctx->async_wait);
	}

	ret = crypto_aead_decrypt(aead_req);
	if (ret == -EINPROGRESS) {
		if (async)
			return ret;

		ret = crypto_wait_req(ret, &ctx->async_wait);
	}

	if (async)
		atomic_dec(&ctx->decrypt_pending);

	return ret;
}

static void tls_trim_both_msgs(struct sock *sk, int target_size)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context_tx *ctx = tls_sw_ctx_tx(tls_ctx);

	sk_msg_trim(sk, &ctx->msg_plaintext, target_size);
	if (target_size > 0)
		target_size += tls_ctx->tx.overhead_size;
	sk_msg_trim(sk, &ctx->msg_encrypted, target_size);
}

static int tls_alloc_encrypted_msg(struct sock *sk, int len)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context_tx *ctx = tls_sw_ctx_tx(tls_ctx);

	return sk_msg_alloc(sk, &ctx->msg_encrypted, len, 0);
}

static int tls_alloc_plaintext_msg(struct sock *sk, int len)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context_tx *ctx = tls_sw_ctx_tx(tls_ctx);
	struct sk_msg *msg_pl = &ctx->msg_plaintext;

	return sk_msg_alloc(sk, msg_pl, len, msg_pl->sg.end - 1);
}

static void tls_free_both_sg(struct sock *sk)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context_tx *ctx = tls_sw_ctx_tx(tls_ctx);

	sk_msg_free(sk, &ctx->msg_encrypted);
	sk_msg_free(sk, &ctx->msg_plaintext);
}

static int tls_do_encryption(struct tls_context *tls_ctx,
			     struct tls_sw_context_tx *ctx,
			     struct aead_request *aead_req,
			     size_t data_len)
{
	struct scatterlist *sge = sk_msg_elem(&ctx->msg_encrypted, 0);
	int rc;

	sge->offset += tls_ctx->tx.prepend_size;
	sge->length -= tls_ctx->tx.prepend_size;

	aead_request_set_tfm(aead_req, ctx->aead_send);
	aead_request_set_ad(aead_req, TLS_AAD_SPACE_SIZE);
	aead_request_set_crypt(aead_req, ctx->sg_aead_in, ctx->sg_aead_out,
			       data_len, tls_ctx->tx.iv);
	aead_request_set_callback(aead_req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				  crypto_req_done, &ctx->async_wait);

	rc = crypto_wait_req(crypto_aead_encrypt(aead_req), &ctx->async_wait);

	sge->offset -= tls_ctx->tx.prepend_size;
	sge->length += tls_ctx->tx.prepend_size;

	return rc;
}

static int tls_push_record(struct sock *sk, int flags,
			   unsigned char record_type)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context_tx *ctx = tls_sw_ctx_tx(tls_ctx);
	struct sk_msg *msg_pl = &ctx->msg_plaintext;
	struct sk_msg *msg_en = &ctx->msg_encrypted;
	int end = msg_pl->sg.end, num_sg = 0;
	int rc, apply, _apply, bytes = 0;
	struct scatterlist tmp = {0};
	struct aead_request *req;
	u32 i;

	req = aead_request_alloc(ctx->aead_send, sk->sk_allocation);
	if (!req)
		return -ENOMEM;

	_apply = apply = msg_pl->apply_bytes;
	if (apply) {
		struct scatterlist *sg;
		int i = msg_pl->sg.start;

	       	sg = sk_msg_elem(msg_pl, i);
		while (apply && sg->length) {
			if (sg->length > apply) {
				int len = sg->length - apply;

 				get_page(sg_page(sg));
				sg_set_page(&tmp, sg_page(sg), len,
					    sg->offset + apply);
				sg->length = apply;
				bytes += apply;
				apply = 0;
			} else {
				num_sg++;
				apply -= sg->length;
				bytes += sg->length;
			}
			
			sk_msg_iter_var(i);
			if (i == msg_pl->sg.end)
				break;
			sg = sk_msg_elem(msg_pl, i);
		}
		end = i;
		sk_msg_trim(sk, msg_en, bytes + tls_ctx->tx.overhead_size);
		msg_pl->apply_bytes = apply;
	} else {
		bytes = msg_pl->sg.size;
	}

	sk_msg_iter_var_prev(end);
	sg_mark_end(sk_msg_elem(msg_pl, end));

	/* If data loops over max elem then we need to chain using
	 * encrypt scatterlist elements before passing to the crypto
	 * engine.
	 */
	if (end < msg_pl->sg.start)
		sg_chain(&msg_pl->sg.data[msg_pl->sg.start],
			 MAX_SKB_FRAGS - msg_pl->sg.start + 1,
		  	 msg_pl->sg.data);	  

	i = msg_pl->sg.start;
	sg_chain(ctx->sg_aead_in, 2, &msg_pl->sg.data[i]);

	i = msg_en->sg.end;
	sk_msg_iter_var_prev(i);
	sg_mark_end(sk_msg_elem(msg_en, i));

	i = msg_en->sg.start;
	sg_chain(ctx->sg_aead_out, 2, &msg_en->sg.data[i]);

	tls_make_aad(ctx->aad_space, bytes,
		     tls_ctx->tx.rec_seq, tls_ctx->tx.rec_seq_size,
		     record_type);

	tls_fill_prepend(tls_ctx,
			 page_address(sg_page(&msg_en->sg.data[i])) +
			 msg_en->sg.data[i].offset, bytes,
			 record_type);

	tls_ctx->pending_open_record_frags = msg_pl->sg.size;
	set_bit(TLS_PENDING_CLOSED_RECORD, &tls_ctx->flags);

	rc = tls_do_encryption(tls_ctx, ctx, req, bytes);
	if (rc < 0) {
		/* If we are called from write_space and
		 * we fail, we need to set this SOCK_NOSPACE
		 * to trigger another write_space in the future.
		 */
		set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
		if (unlikely(tmp.length)) {
			i = end;
			sk_msg_iter_var_prev(i);

			/* Encrypt failed add tmp bytes back onto sg.data
			 * do we also need to reset apply_bytes?
			 */
			msg_pl->sg.data[i].length += tmp.length;
		}
		goto out_req;
	}

	sk_msg_free_partial(sk, msg_pl, bytes);
	if (tmp.length) {
		sk_msg_prev(msg_pl, start);
		msg_pl->sg.data[msg_pl->sg.start] = tmp;
	} else if (!msg_pl->sg.data[msg_pl->sg.start].length) {
		sk_msg_init(msg_pl, false);
	}

	memset(&msg_en->sg, 0, offsetofend(struct sk_msg_sg, copy));

	/* Only pass through MSG_DONTWAIT and MSG_NOSIGNAL flags */
	rc = tls_push_sg(sk, tls_ctx, &msg_en->sg.data[i], 0, flags);
	if (rc < 0 && rc != -EAGAIN)
		tls_err_abort(sk, EBADMSG);

	tls_advance_record_sn(sk, &tls_ctx->tx);
out_req:
	aead_request_free(req);
	return rc;
}

static int bpf_exec_tx_verdict(struct sk_msg *m,
			       struct sock *sk,
			       unsigned char record_type,
			       size_t *copied, int flags)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct sk_msg mredir = {0};
	struct sk_psock *psock;
	struct sock *redir;
	int err = 0, send;
	bool enospc;

	psock = sk_psock_get(sk);
	if (!psock)
		return tls_push_record(sk, flags, record_type);
more_data:
	enospc = (m->sg.start == m->sg.end);
 	if (psock->eval == __SK_NONE)
		psock->eval = sk_psock_msg_verdict(sk, psock, m);
 	if (m->cork_bytes && m->cork_bytes > m->sg.size && !enospc) {
		err = -ENOSPC;
		goto out_err;
	}
 	m->cork_bytes = 0;
	send = m->sg.size;
	if (m->apply_bytes && m->apply_bytes < send)
		send = m->apply_bytes;
 	switch (psock->eval) {
	case __SK_PASS:
		err = tls_push_record(sk, flags, record_type);
		if (unlikely(err < 0)) {
			*copied -= m->sg.size;
			sk_msg_free(sk, m);
			goto out_err;
		}
		break;
	case __SK_REDIRECT:
		redir = psock->sk_redir;
		memcpy(&mredir, m, sizeof(*m));
		if (m->apply_bytes < send)
			m->apply_bytes = 0;
		else
			m->apply_bytes -= send;
		sk_msg_return_zero(sk, m, send);
		m->sg.size -= send;
		release_sock(sk);
 		err = tcp_bpf_sendmsg_redir(redir, &mredir, send, flags);
 		lock_sock(sk);
		if (err < 0) {
			*copied -= sk_msg_free_nocharge(sk, &mredir);
			m->sg.size = 0;
		}
		break;
	case __SK_DROP:
	default:
		sk_msg_free_partial(sk, m, send);
		if (m->apply_bytes < send)
			m->apply_bytes = 0;
		else
			m->apply_bytes -= send;
		*copied -= send;
		return -EACCES;
	}
 	if (likely(!err)) {
		if (!m->apply_bytes) {
			psock->eval = __SK_NONE;
			if (psock->sk_redir) {
				sock_put(psock->sk_redir);
				psock->sk_redir = NULL;
			}
		}
		if (m &&
		    m->sg.data[m->sg.start].page_link &&
		    m->sg.data[m->sg.start].length) {
			err = tls_alloc_encrypted_msg(sk, m->sg.size + tls_ctx->tx.overhead_size);
			if (likely(!err))
				goto more_data;
			*copied -= sk_msg_free(sk, m);
		}
	}
 out_err:
	/* Avoid chaining elements for encryption by checking empty buffer
	 * and zero'ing data. However we may have outstanding data if (a)
	 * there is an error case or (b) we are cork'ing data.
	 */
	if (m->sg.start == m->sg.end && !m->sg.data[m->sg.start].length)
		m->sg.start = m->sg.end = 0;
	sk_psock_put(sk, psock);
	return err;
}

/* TBD: verify we hit this in a case without cork'd result so that we
 * run through data path.
 */
static int tls_sw_push_pending_record(struct sock *sk, int flags)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context_tx *ctx = tls_sw_ctx_tx(tls_ctx);
	struct sk_msg *msg_pl = &ctx->msg_plaintext;
	size_t copied = msg_pl->sg.size;

	if (!msg_pl->sg.size)
		return 0;

	return bpf_exec_tx_verdict(msg_pl, sk, TLS_RECORD_TYPE_DATA, &copied, flags);
}

int tls_sw_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context_tx *ctx = tls_sw_ctx_tx(tls_ctx);
	struct sk_msg *msg_pl = &ctx->msg_plaintext;
	struct sk_msg *msg_en = &ctx->msg_encrypted;
	int ret = 0, required_size, orig_size, record_room;
	long timeo = sock_sndtimeo(sk, msg->msg_flags & MSG_DONTWAIT);
	bool full_record, eor = !(msg->msg_flags & MSG_MORE);
	size_t try_to_copy, copied = 0;
	unsigned char record_type = TLS_RECORD_TYPE_DATA;
	bool is_kvec = msg->msg_iter.type & ITER_KVEC;

	if (msg->msg_flags & ~(MSG_MORE | MSG_DONTWAIT | MSG_NOSIGNAL))
		return -ENOTSUPP;

	lock_sock(sk);

	if (tls_complete_pending_work(sk, tls_ctx, msg->msg_flags, &timeo))
		goto send_end;

	if (unlikely(msg->msg_controllen)) {
		ret = tls_proccess_cmsg(sk, msg, &record_type);
		if (ret)
			goto send_end;
	}

	while (msg_data_left(msg)) {
		if (sk->sk_err) {
			ret = -sk->sk_err;
			goto send_end;
		}

		orig_size = msg_pl->sg.size;
		full_record = false;
		try_to_copy = msg_data_left(msg);
		record_room = TLS_MAX_PAYLOAD_SIZE - msg_pl->sg.size;
		if (try_to_copy >= record_room) {
			try_to_copy = record_room;
			full_record = true;
		}

		required_size = msg_pl->sg.size + try_to_copy +
				tls_ctx->tx.overhead_size;

		if (!sk_stream_memory_free(sk))
			goto wait_for_sndbuf;
alloc_encrypted:
		ret = tls_alloc_encrypted_msg(sk, required_size);
		if (ret) {
			if (ret != -ENOSPC)
				goto wait_for_memory;

			/* Adjust try_to_copy according to the amount that was
			 * actually allocated. The difference is due
			 * to max sg elements limit
			 */
			try_to_copy -= required_size - msg_en->sg.size;
			full_record = true;
		}

		if (!is_kvec && (full_record || eor)) {
			int first = msg_pl->sg.end;

			ret = sk_msg_zerocopy_from_iter(sk, &msg->msg_iter,
							msg_pl,
							try_to_copy);
			if (ret)
				goto fallback_to_reg_send;

			copied += try_to_copy;
			sk_msg_sg_copy_set(msg_pl, first);
			ret = bpf_exec_tx_verdict(msg_pl, sk, record_type,
						  &copied,
						  msg->msg_flags);
			if (!ret)
				continue;
			else if (ret == -EAGAIN || ret == -EACCES)
				goto send_end;
			else if (ret != -ENOSPC)
				goto wait_for_memory;

			copied -= try_to_copy;
			sk_msg_sg_copy_clear(msg_pl, first);
			iov_iter_revert(&msg->msg_iter,
					msg_pl->sg.size - orig_size);
fallback_to_reg_send:
			sk_msg_trim(sk, msg_pl, orig_size);
		}

		required_size = msg_pl->sg.size + try_to_copy;
alloc_plaintext:
		ret = tls_alloc_plaintext_msg(sk, required_size);
		if (ret) {
			if (ret != -ENOSPC)
				goto wait_for_memory;

			/* Adjust try_to_copy according to the amount that was
			 * actually allocated. The difference is due
			 * to max sg elements limit
			 */
			try_to_copy -= required_size - msg_pl->sg.size;
			full_record = true;
			sk_msg_trim(sk, msg_en, msg_pl->sg.size +
				    tls_ctx->tx.overhead_size);
		}

		ret = sk_msg_memcopy_from_iter(sk, &msg->msg_iter, msg_pl,
					       try_to_copy);
		if (ret < 0)
			goto trim_sgl;
		/* open records defined only if successful copy otherwise we would
		 * trim the sg but not reset the open record frags.
		 */
		tls_ctx->pending_open_record_frags = msg_pl->sg.size;
		copied += try_to_copy;
		if (full_record || eor) {
push_record:
			ret = bpf_exec_tx_verdict(msg_pl, sk, record_type,
						  &copied,
						  msg->msg_flags);
			if (ret) {
				if (ret == -ENOMEM)
					goto wait_for_memory;
				else if (ret == -ENOSPC)
					ret = 0;
				goto send_end;
			}
		}

		continue;

wait_for_sndbuf:
		set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
wait_for_memory:
		ret = sk_stream_wait_memory(sk, &timeo);
		if (ret) {
trim_sgl:
			tls_trim_both_msgs(sk, orig_size);
			goto send_end;
		}

		if (tls_is_pending_closed_record(tls_ctx))
			goto push_record;

		if (msg_en->sg.size < required_size)
			goto alloc_encrypted;

		goto alloc_plaintext;
	}

send_end:
	ret = sk_stream_error(sk, msg->msg_flags, ret);

	release_sock(sk);
	return copied ? copied : ret;
}

int tls_sw_sendpage(struct sock *sk, struct page *page,
		    int offset, size_t size, int flags)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context_tx *ctx = tls_sw_ctx_tx(tls_ctx);
	struct sk_msg *msg_pl = &ctx->msg_plaintext;
	int ret = 0, record_room;
	long timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);
	bool full_record, eor;
	size_t copied = 0;
	unsigned char record_type = TLS_RECORD_TYPE_DATA;

	if (flags & ~(MSG_MORE | MSG_DONTWAIT | MSG_NOSIGNAL |
		      MSG_SENDPAGE_NOTLAST))
		return -ENOTSUPP;

	/* No MSG_EOR from splice, only look at MSG_MORE */
	eor = !(flags & (MSG_MORE | MSG_SENDPAGE_NOTLAST));

	lock_sock(sk);

	sk_clear_bit(SOCKWQ_ASYNC_NOSPACE, sk);

	if (tls_complete_pending_work(sk, tls_ctx, flags, &timeo))
		goto sendpage_end;

	/* Call the sk_stream functions to manage the sndbuf mem. */
	while (size > 0) {
		size_t copy, required_size;

		if (sk->sk_err) {
			ret = -sk->sk_err;
			goto sendpage_end;
		}

		full_record = false;
		record_room = TLS_MAX_PAYLOAD_SIZE - msg_pl->sg.size;
		copied = 0;
		copy = size;
		if (copy >= record_room) {
			copy = record_room;
			full_record = true;
		}
		required_size = msg_pl->sg.size + copy +
				tls_ctx->tx.overhead_size;

		if (!sk_stream_memory_free(sk))
			goto wait_for_sndbuf;
alloc_payload:
		ret = tls_alloc_encrypted_msg(sk, required_size);
		if (ret) {
			if (ret != -ENOSPC)
				goto wait_for_memory;

			/* Adjust copy according to the amount that was
			 * actually allocated. The difference is due
			 * to max sg elements limit
			 */
			copy -= required_size - msg_pl->sg.size;
			full_record = true;
		}

		sk_msg_page_add(msg_pl, page, copy, offset);
		sk_mem_charge(sk, copy);

		offset += copy;
		size -= copy;
		copied += copy;

		// TBD: needs to be distance not end :/
		//tls_ctx->pending_open_record_frags = msg_pl->sg.end;
		if (full_record || eor || sk_msg_full(msg_pl)) {
push_record:
			ret = bpf_exec_tx_verdict(msg_pl, sk, record_type,
						  &copied,
						  flags);
			if (ret) {
				if (ret == -ENOMEM)
					goto wait_for_memory;
				else if (ret == -ENOSPC)
					ret = 0;

				goto sendpage_end;
			}
		}
		continue;
wait_for_sndbuf:
		set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
wait_for_memory:
		ret = sk_stream_wait_memory(sk, &timeo);
		if (ret) {
			tls_trim_both_msgs(sk, msg_pl->sg.size);
			goto sendpage_end;
		}

		if (tls_is_pending_closed_record(tls_ctx))
			goto push_record;

		goto alloc_payload;
	}

sendpage_end:
	ret = sk_stream_error(sk, flags, ret);
	release_sock(sk);
	return copied ? copied : ret;
}

static struct sk_buff *tls_wait_data(struct sock *sk, struct sk_psock *psock,
				     int flags, long timeo, int *err)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context_rx *ctx = tls_sw_ctx_rx(tls_ctx);
	struct sk_buff *skb;
	DEFINE_WAIT_FUNC(wait, woken_wake_function);

	while (!(skb = ctx->recv_pkt) &&
	       (psock ? list_empty(&psock->ingress_msg) : true)) {
		if (sk->sk_err) {
			*err = sock_error(sk);
			return NULL;
		}

		if (sk->sk_shutdown & RCV_SHUTDOWN)
			return NULL;

		if (sock_flag(sk, SOCK_DONE))
			return NULL;

		if ((flags & MSG_DONTWAIT) || !timeo) {
			*err = -EAGAIN;
			return NULL;
		}

		add_wait_queue(sk_sleep(sk), &wait);
		sk_set_bit(SOCKWQ_ASYNC_WAITDATA, sk);
		sk_wait_event(sk, &timeo,
			      ctx->recv_pkt != skb ||
			      !(psock ? list_empty(&psock->ingress_msg) : true),
			      &wait);
		sk_clear_bit(SOCKWQ_ASYNC_WAITDATA, sk);
		remove_wait_queue(sk_sleep(sk), &wait);

		/* Handle signals */
		if (signal_pending(current)) {
			*err = sock_intr_errno(timeo);
			return NULL;
		}
	}

	return skb;
}

static int tls_setup_from_iter(struct sock *sk, struct iov_iter *from,
			       int length, int *pages_used,
			       unsigned int *size_used,
			       struct scatterlist *to,
			       int to_max_pages)
{
	int rc = 0, i = 0, num_elem = *pages_used, maxpages;
	struct page *pages[MAX_SKB_FRAGS];
	unsigned int size = *size_used;
	ssize_t copied, use;
	size_t offset;

	while (length > 0) {
		i = 0;
		maxpages = to_max_pages - num_elem;
		if (maxpages == 0) {
			rc = -EFAULT;
			goto out;
		}
		copied = iov_iter_get_pages(from, pages,
					    length,
					    maxpages, &offset);
		if (copied <= 0) {
			rc = -EFAULT;
			goto out;
		}

		iov_iter_advance(from, copied);

		length -= copied;
		size += copied;
		while (copied) {
			use = min_t(int, copied, PAGE_SIZE - offset);

			sg_set_page(&to[num_elem],
				    pages[i], use, offset);
			sg_unmark_end(&to[num_elem]);
			/* We do not uncharge memory from this API */

			offset = 0;
			copied -= use;

			i++;
			num_elem++;
		}
	}
	/* Mark the end in the last sg entry if newly added */
	if (num_elem > *pages_used)
		sg_mark_end(&to[num_elem - 1]);
out:
	if (rc)
		iov_iter_revert(from, size - *size_used);
	*size_used = size;
	*pages_used = num_elem;

	return rc;
}

/* This function decrypts the input skb into either out_iov or in out_sg
 * or in skb buffers itself. The input parameter 'zc' indicates if
 * zero-copy mode needs to be tried or not. With zero-copy mode, either
 * out_iov or out_sg must be non-NULL. In case both out_iov and out_sg are
 * NULL, then the decryption happens inside skb buffers itself, i.e.
 * zero-copy gets disabled and 'zc' is updated.
 */

static int decrypt_internal(struct sock *sk, struct sk_buff *skb,
			    struct iov_iter *out_iov,
			    struct scatterlist *out_sg,
			    int *chunk, bool *zc)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context_rx *ctx = tls_sw_ctx_rx(tls_ctx);
	struct strp_msg *rxm = strp_msg(skb);
	int n_sgin, n_sgout, nsg, mem_size, aead_size, err, pages = 0;
	struct aead_request *aead_req;
	struct sk_buff *unused;
	u8 *aad, *iv, *mem = NULL;
	struct scatterlist *sgin = NULL;
	struct scatterlist *sgout = NULL;
	const int data_len = rxm->full_len - tls_ctx->rx.overhead_size;

	if (*zc && (out_iov || out_sg)) {
		if (out_iov)
			n_sgout = iov_iter_npages(out_iov, INT_MAX) + 1;
		else
			n_sgout = sg_nents(out_sg);
		n_sgin = skb_nsg(skb, rxm->offset + tls_ctx->rx.prepend_size,
				 rxm->full_len - tls_ctx->rx.prepend_size);
	} else {
		n_sgout = 0;
		*zc = false;
		n_sgin = skb_cow_data(skb, 0, &unused);
	}

	if (n_sgin < 1)
		return -EBADMSG;

	/* Increment to accommodate AAD */
	n_sgin = n_sgin + 1;

	nsg = n_sgin + n_sgout;

	aead_size = sizeof(*aead_req) + crypto_aead_reqsize(ctx->aead_recv);
	mem_size = aead_size + (nsg * sizeof(struct scatterlist));
	mem_size = mem_size + TLS_AAD_SPACE_SIZE;
	mem_size = mem_size + crypto_aead_ivsize(ctx->aead_recv);

	/* Allocate a single block of memory which contains
	 * aead_req || sgin[] || sgout[] || aad || iv.
	 * This order achieves correct alignment for aead_req, sgin, sgout.
	 */
	mem = kmalloc(mem_size, sk->sk_allocation);
	if (!mem)
		return -ENOMEM;

	/* Segment the allocated memory */
	aead_req = (struct aead_request *)mem;
	sgin = (struct scatterlist *)(mem + aead_size);
	sgout = sgin + n_sgin;
	aad = (u8 *)(sgout + n_sgout);
	iv = aad + TLS_AAD_SPACE_SIZE;

	/* Prepare IV */
	err = skb_copy_bits(skb, rxm->offset + TLS_HEADER_SIZE,
			    iv + TLS_CIPHER_AES_GCM_128_SALT_SIZE,
			    tls_ctx->rx.iv_size);
	if (err < 0) {
		kfree(mem);
		return err;
	}
	memcpy(iv, tls_ctx->rx.iv, TLS_CIPHER_AES_GCM_128_SALT_SIZE);

	/* Prepare AAD */
	tls_make_aad(aad, rxm->full_len - tls_ctx->rx.overhead_size,
		     tls_ctx->rx.rec_seq, tls_ctx->rx.rec_seq_size,
		     ctx->control);

	/* Prepare sgin */
	sg_init_table(sgin, n_sgin);
	sg_set_buf(&sgin[0], aad, TLS_AAD_SPACE_SIZE);
	err = skb_to_sgvec(skb, &sgin[1],
			   rxm->offset + tls_ctx->rx.prepend_size,
			   rxm->full_len - tls_ctx->rx.prepend_size);
	if (err < 0) {
		kfree(mem);
		return err;
	}

	if (n_sgout) {
		if (out_iov) {
			sg_init_table(sgout, n_sgout);
			sg_set_buf(&sgout[0], aad, TLS_AAD_SPACE_SIZE);

			*chunk = 0;
			err = tls_setup_from_iter(sk, out_iov, data_len,
						  &pages, chunk, &sgout[1],
						  (n_sgout - 1));
			if (err < 0)
				goto fallback_to_reg_recv;
		} else if (out_sg) {
			memcpy(sgout, out_sg, n_sgout * sizeof(*sgout));
		} else {
			goto fallback_to_reg_recv;
		}
	} else {
fallback_to_reg_recv:
		sgout = sgin;
		pages = 0;
		*chunk = 0;
		*zc = false;
	}

	/* Prepare and submit AEAD request */
	err = tls_do_decryption(sk, skb, sgin, sgout, iv,
				data_len, aead_req, *zc);
	if (err == -EINPROGRESS)
		return err;

	/* Release the pages in case iov was mapped to pages */
	for (; pages > 0; pages--)
		put_page(sg_page(&sgout[pages]));

	kfree(mem);
	return err;
}

static int decrypt_skb_update(struct sock *sk, struct sk_buff *skb,
			      struct iov_iter *dest, int *chunk, bool *zc)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context_rx *ctx = tls_sw_ctx_rx(tls_ctx);
	struct strp_msg *rxm = strp_msg(skb);
	int err = 0;

#ifdef CONFIG_TLS_DEVICE
	err = tls_device_decrypted(sk, skb);
	if (err < 0)
		return err;
#endif
	if (!ctx->decrypted) {
		err = decrypt_internal(sk, skb, dest, NULL, chunk, zc);
		if (err < 0) {
			if (err == -EINPROGRESS)
				tls_advance_record_sn(sk, &tls_ctx->rx);

			return err;
		}
	} else {
		*zc = false;
	}

	rxm->offset += tls_ctx->rx.prepend_size;
	rxm->full_len -= tls_ctx->rx.overhead_size;
	tls_advance_record_sn(sk, &tls_ctx->rx);
	ctx->decrypted = true;
	ctx->saved_data_ready(sk);

	return err;
}

int decrypt_skb(struct sock *sk, struct sk_buff *skb,
		struct scatterlist *sgout)
{
	bool zc = true;
	int chunk;

	return decrypt_internal(sk, skb, NULL, sgout, &chunk, &zc);
}

static bool tls_sw_advance_skb(struct sock *sk, struct sk_buff *skb,
			       unsigned int len)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context_rx *ctx = tls_sw_ctx_rx(tls_ctx);

	if (skb) {
		struct strp_msg *rxm = strp_msg(skb);

		if (len < rxm->full_len) {
			rxm->offset += len;
			rxm->full_len -= len;
			return false;
		}
		kfree_skb(skb);
	}

	/* Finished with message */
	ctx->recv_pkt = NULL;
	__strp_unpause(&ctx->strp);

	return true;
}

int tls_sw_recvmsg(struct sock *sk,
		   struct msghdr *msg,
		   size_t len,
		   int nonblock,
		   int flags,
		   int *addr_len)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context_rx *ctx = tls_sw_ctx_rx(tls_ctx);
	struct sk_psock *psock;
	unsigned char control;
	struct strp_msg *rxm;
	struct sk_buff *skb;
	ssize_t copied = 0;
	bool cmsg = false;
	int target, err = 0;
	long timeo;
	bool is_kvec = msg->msg_iter.type & ITER_KVEC;
	int num_async = 0;

	flags |= nonblock;

	if (unlikely(flags & MSG_ERRQUEUE))
		return sock_recv_errqueue(sk, msg, len, SOL_IP, IP_RECVERR);

	psock= sk_psock_get(sk);
	lock_sock(sk);

	target = sock_rcvlowat(sk, flags & MSG_WAITALL, len);
	timeo = sock_rcvtimeo(sk, flags & MSG_DONTWAIT);
	do {
		bool zc = false;
		bool async = false;
		int chunk = 0;

		skb = tls_wait_data(sk, psock, flags, timeo, &err);
		if (!skb) {
			if (psock) {
				int r = __tcp_bpf_recvmsg(sk, psock, msg, len);

				if (r > 0) {
					copied += r;
					len -= r;
					continue;
				}
			}
			goto recv_end;
		}

		rxm = strp_msg(skb);

		if (!cmsg) {
			int cerr;

			cerr = put_cmsg(msg, SOL_TLS, TLS_GET_RECORD_TYPE,
					sizeof(ctx->control), &ctx->control);
			cmsg = true;
			control = ctx->control;
			if (ctx->control != TLS_RECORD_TYPE_DATA) {
				if (cerr || msg->msg_flags & MSG_CTRUNC) {
					err = -EIO;
					goto recv_end;
				}
			}
		} else if (control != ctx->control) {
			goto recv_end;
		}

		if (!ctx->decrypted) {
			int to_copy = rxm->full_len - tls_ctx->rx.overhead_size;

			if (!is_kvec && to_copy <= len &&
			    likely(!(flags & MSG_PEEK)))
				zc = true;

			err = decrypt_skb_update(sk, skb, &msg->msg_iter,
						 &chunk, &zc);
			if (err < 0 && err != -EINPROGRESS) {
				tls_err_abort(sk, EBADMSG);
				goto recv_end;
			}

			if (err == -EINPROGRESS) {
				async = true;
				num_async++;
				goto pick_next_record;
			}

			ctx->decrypted = true;
		}

		if (!zc) {
			chunk = min_t(unsigned int, rxm->full_len, len);

			err = skb_copy_datagram_msg(skb, rxm->offset, msg,
						    chunk);
			if (err < 0)
				goto recv_end;
		}

pick_next_record:
		copied += chunk;
		len -= chunk;
		if (likely(!(flags & MSG_PEEK))) {
			u8 control = ctx->control;

			/* For async, drop current skb reference */
			if (async)
				skb = NULL;

			if (tls_sw_advance_skb(sk, skb, chunk)) {
				/* Return full control message to
				 * userspace before trying to parse
				 * another message type
				 */
				msg->msg_flags |= MSG_EOR;
				if (control != TLS_RECORD_TYPE_DATA)
					goto recv_end;
			} else {
				break;
			}
		}

		/* If we have a new message from strparser, continue now. */
		if (copied >= target && !ctx->recv_pkt)
			break;
	} while (len);

recv_end:
	if (num_async) {
		/* Wait for all previously submitted records to be decrypted */
		smp_store_mb(ctx->async_notify, true);
		if (atomic_read(&ctx->decrypt_pending)) {
			err = crypto_wait_req(-EINPROGRESS, &ctx->async_wait);
			if (err) {
				/* one of async decrypt failed */
				tls_err_abort(sk, err);
				copied = 0;
			}
		} else {
			reinit_completion(&ctx->async_wait.completion);
		}
		WRITE_ONCE(ctx->async_notify, false);
	}

	release_sock(sk);
	if (psock)
		sk_psock_put(sk, psock);
	return copied ? : err;
}

ssize_t tls_sw_splice_read(struct socket *sock,  loff_t *ppos,
			   struct pipe_inode_info *pipe,
			   size_t len, unsigned int flags)
{
	struct tls_context *tls_ctx = tls_get_ctx(sock->sk);
	struct tls_sw_context_rx *ctx = tls_sw_ctx_rx(tls_ctx);
	struct strp_msg *rxm = NULL;
	struct sock *sk = sock->sk;
	struct sk_buff *skb;
	ssize_t copied = 0;
	int err = 0;
	long timeo;
	int chunk;
	bool zc = false;

	lock_sock(sk);

	timeo = sock_rcvtimeo(sk, flags & MSG_DONTWAIT);

	skb = tls_wait_data(sk, NULL, flags, timeo, &err);
	if (!skb)
		goto splice_read_end;

	/* splice does not support reading control messages */
	if (ctx->control != TLS_RECORD_TYPE_DATA) {
		err = -ENOTSUPP;
		goto splice_read_end;
	}

	if (!ctx->decrypted) {
		err = decrypt_skb_update(sk, skb, NULL, &chunk, &zc);

		if (err < 0) {
			tls_err_abort(sk, EBADMSG);
			goto splice_read_end;
		}
		ctx->decrypted = true;
	}
	rxm = strp_msg(skb);

	chunk = min_t(unsigned int, rxm->full_len, len);
	copied = skb_splice_bits(skb, sk, rxm->offset, pipe, chunk, flags);
	if (copied < 0)
		goto splice_read_end;

	if (likely(!(flags & MSG_PEEK)))
		tls_sw_advance_skb(sk, skb, copied);

splice_read_end:
	release_sock(sk);
	return copied ? : err;
}

bool tls_sw_stream_read(const struct sock *sk)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context_rx *ctx = tls_sw_ctx_rx(tls_ctx);
	bool ingress_empty = true;
	struct sk_psock *psock;

	rcu_read_lock();
	psock = sk_psock(sk);
	if (psock)
		ingress_empty = list_empty(&psock->ingress_msg);
	rcu_read_unlock();

	return !ingress_empty || ctx->recv_pkt;
}

static int tls_read_size(struct strparser *strp, struct sk_buff *skb)
{
	struct tls_context *tls_ctx = tls_get_ctx(strp->sk);
	struct tls_sw_context_rx *ctx = tls_sw_ctx_rx(tls_ctx);
	char header[TLS_HEADER_SIZE + MAX_IV_SIZE];
	struct strp_msg *rxm = strp_msg(skb);
	size_t cipher_overhead;
	size_t data_len = 0;
	int ret;

	/* Verify that we have a full TLS header, or wait for more data */
	if (rxm->offset + tls_ctx->rx.prepend_size > skb->len)
		return 0;

	/* Sanity-check size of on-stack buffer. */
	if (WARN_ON(tls_ctx->rx.prepend_size > sizeof(header))) {
		ret = -EINVAL;
		goto read_failure;
	}

	/* Linearize header to local buffer */
	ret = skb_copy_bits(skb, rxm->offset, header, tls_ctx->rx.prepend_size);

	if (ret < 0)
		goto read_failure;

	ctx->control = header[0];

	data_len = ((header[4] & 0xFF) | (header[3] << 8));

	cipher_overhead = tls_ctx->rx.tag_size + tls_ctx->rx.iv_size;

	if (data_len > TLS_MAX_PAYLOAD_SIZE + cipher_overhead) {
		ret = -EMSGSIZE;
		goto read_failure;
	}
	if (data_len < cipher_overhead) {
		ret = -EBADMSG;
		goto read_failure;
	}

	if (header[1] != TLS_VERSION_MINOR(tls_ctx->crypto_recv.version) ||
	    header[2] != TLS_VERSION_MAJOR(tls_ctx->crypto_recv.version)) {
		ret = -EINVAL;
		goto read_failure;
	}

#ifdef CONFIG_TLS_DEVICE
	handle_device_resync(strp->sk, TCP_SKB_CB(skb)->seq + rxm->offset,
			     *(u64*)tls_ctx->rx.rec_seq);
#endif
	return data_len + TLS_HEADER_SIZE;

read_failure:
	tls_err_abort(strp->sk, ret);

	return ret;
}

static void tls_queue(struct strparser *strp, struct sk_buff *skb)
{
	struct tls_context *tls_ctx = tls_get_ctx(strp->sk);
	struct tls_sw_context_rx *ctx = tls_sw_ctx_rx(tls_ctx);

	ctx->decrypted = false;

	ctx->recv_pkt = skb;
	strp_pause(strp);

	ctx->saved_data_ready(strp->sk);
}

static void tls_data_ready(struct sock *sk)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context_rx *ctx = tls_sw_ctx_rx(tls_ctx);
	struct sk_psock *psock;

	strp_data_ready(&ctx->strp);

	psock = sk_psock_get(sk);
	if (psock && !list_empty(&psock->ingress_msg)) {
		ctx->saved_data_ready(sk);
		sk_psock_put(sk, psock);
	}
}

void tls_sw_free_resources_tx(struct sock *sk)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context_tx *ctx = tls_sw_ctx_tx(tls_ctx);

	crypto_free_aead(ctx->aead_send);
	tls_free_both_sg(sk);

	kfree(ctx);
}

void tls_sw_release_resources_rx(struct sock *sk)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context_rx *ctx = tls_sw_ctx_rx(tls_ctx);

	if (ctx->aead_recv) {
		kfree_skb(ctx->recv_pkt);
		ctx->recv_pkt = NULL;
		crypto_free_aead(ctx->aead_recv);
		strp_stop(&ctx->strp);
		write_lock_bh(&sk->sk_callback_lock);
		sk->sk_data_ready = ctx->saved_data_ready;
		write_unlock_bh(&sk->sk_callback_lock);
		release_sock(sk);
		strp_done(&ctx->strp);
		lock_sock(sk);
	}
}

void tls_sw_free_resources_rx(struct sock *sk)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context_rx *ctx = tls_sw_ctx_rx(tls_ctx);

	tls_sw_release_resources_rx(sk);

	kfree(ctx);
}

int tls_set_sw_offload(struct sock *sk, struct tls_context *ctx, int tx)
{
	char keyval[TLS_CIPHER_AES_GCM_128_KEY_SIZE];
	struct tls_crypto_info *crypto_info;
	struct tls12_crypto_info_aes_gcm_128 *gcm_128_info;
	struct tls_sw_context_tx *sw_ctx_tx = NULL;
	struct tls_sw_context_rx *sw_ctx_rx = NULL;
	struct cipher_context *cctx;
	struct crypto_aead **aead;
	struct strp_callbacks cb;
	u16 nonce_size, tag_size, iv_size, rec_seq_size;
	char *iv, *rec_seq;
	int rc = 0;

	if (!ctx) {
		rc = -EINVAL;
		goto out;
	}

	if (tx) {
		if (!ctx->priv_ctx_tx) {
			sw_ctx_tx = kzalloc(sizeof(*sw_ctx_tx), GFP_KERNEL);
			if (!sw_ctx_tx) {
				rc = -ENOMEM;
				goto out;
			}
			ctx->priv_ctx_tx = sw_ctx_tx;
		} else {
			sw_ctx_tx =
				(struct tls_sw_context_tx *)ctx->priv_ctx_tx;
		}
	} else {
		if (!ctx->priv_ctx_rx) {
			sw_ctx_rx = kzalloc(sizeof(*sw_ctx_rx), GFP_KERNEL);
			if (!sw_ctx_rx) {
				rc = -ENOMEM;
				goto out;
			}
			ctx->priv_ctx_rx = sw_ctx_rx;
		} else {
			sw_ctx_rx =
				(struct tls_sw_context_rx *)ctx->priv_ctx_rx;
		}
	}

	if (tx) {
		crypto_init_wait(&sw_ctx_tx->async_wait);
		crypto_info = &ctx->crypto_send;
		cctx = &ctx->tx;
		aead = &sw_ctx_tx->aead_send;
	} else {
		crypto_init_wait(&sw_ctx_rx->async_wait);
		crypto_info = &ctx->crypto_recv;
		cctx = &ctx->rx;
		aead = &sw_ctx_rx->aead_recv;
	}

	switch (crypto_info->cipher_type) {
	case TLS_CIPHER_AES_GCM_128: {
		nonce_size = TLS_CIPHER_AES_GCM_128_IV_SIZE;
		tag_size = TLS_CIPHER_AES_GCM_128_TAG_SIZE;
		iv_size = TLS_CIPHER_AES_GCM_128_IV_SIZE;
		iv = ((struct tls12_crypto_info_aes_gcm_128 *)crypto_info)->iv;
		rec_seq_size = TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE;
		rec_seq =
		 ((struct tls12_crypto_info_aes_gcm_128 *)crypto_info)->rec_seq;
		gcm_128_info =
			(struct tls12_crypto_info_aes_gcm_128 *)crypto_info;
		break;
	}
	default:
		rc = -EINVAL;
		goto free_priv;
	}

	/* Sanity-check the IV size for stack allocations. */
	if (iv_size > MAX_IV_SIZE || nonce_size > MAX_IV_SIZE) {
		rc = -EINVAL;
		goto free_priv;
	}

	cctx->prepend_size = TLS_HEADER_SIZE + nonce_size;
	cctx->tag_size = tag_size;
	cctx->overhead_size = cctx->prepend_size + cctx->tag_size;
	cctx->iv_size = iv_size;
	cctx->iv = kmalloc(iv_size + TLS_CIPHER_AES_GCM_128_SALT_SIZE,
			   GFP_KERNEL);
	if (!cctx->iv) {
		rc = -ENOMEM;
		goto free_priv;
	}
	memcpy(cctx->iv, gcm_128_info->salt, TLS_CIPHER_AES_GCM_128_SALT_SIZE);
	memcpy(cctx->iv + TLS_CIPHER_AES_GCM_128_SALT_SIZE, iv, iv_size);
	cctx->rec_seq_size = rec_seq_size;
	cctx->rec_seq = kmemdup(rec_seq, rec_seq_size, GFP_KERNEL);
	if (!cctx->rec_seq) {
		rc = -ENOMEM;
		goto free_iv;
	}

	if (sw_ctx_tx) {
		struct sk_msg *msg_pl = &sw_ctx_tx->msg_plaintext;
		struct sk_msg *msg_en = &sw_ctx_tx->msg_encrypted;

		sk_msg_init(msg_pl, true);
		sk_msg_init(msg_en, true);

		sg_init_table(sw_ctx_tx->sg_aead_in, 2);
		sg_set_buf(&sw_ctx_tx->sg_aead_in[0], sw_ctx_tx->aad_space,
			   sizeof(sw_ctx_tx->aad_space));
		sg_unmark_end(&sw_ctx_tx->sg_aead_in[1]);
		sg_chain(sw_ctx_tx->sg_aead_in, 2, msg_pl->sg.data);

		sg_init_table(sw_ctx_tx->sg_aead_out, 2);
		sg_set_buf(&sw_ctx_tx->sg_aead_out[0], sw_ctx_tx->aad_space,
			   sizeof(sw_ctx_tx->aad_space));
		sg_unmark_end(&sw_ctx_tx->sg_aead_out[1]);
		sg_chain(sw_ctx_tx->sg_aead_out, 2, msg_en->sg.data);
	}

	if (!*aead) {
		*aead = crypto_alloc_aead("gcm(aes)", 0, 0);
		if (IS_ERR(*aead)) {
			rc = PTR_ERR(*aead);
			*aead = NULL;
			goto free_rec_seq;
		}
	}

	ctx->push_pending_record = tls_sw_push_pending_record;

	memcpy(keyval, gcm_128_info->key, TLS_CIPHER_AES_GCM_128_KEY_SIZE);

	rc = crypto_aead_setkey(*aead, keyval,
				TLS_CIPHER_AES_GCM_128_KEY_SIZE);
	if (rc)
		goto free_aead;

	rc = crypto_aead_setauthsize(*aead, cctx->tag_size);
	if (rc)
		goto free_aead;

	if (sw_ctx_rx) {
		/* Set up strparser */
		memset(&cb, 0, sizeof(cb));
		cb.rcv_msg = tls_queue;
		cb.parse_msg = tls_read_size;

		strp_init(&sw_ctx_rx->strp, sk, &cb);

		write_lock_bh(&sk->sk_callback_lock);
		sw_ctx_rx->saved_data_ready = sk->sk_data_ready;
		sk->sk_data_ready = tls_data_ready;
		write_unlock_bh(&sk->sk_callback_lock);

		strp_check_rcv(&sw_ctx_rx->strp);
	}

	goto out;

free_aead:
	crypto_free_aead(*aead);
	*aead = NULL;
free_rec_seq:
	kfree(cctx->rec_seq);
	cctx->rec_seq = NULL;
free_iv:
	kfree(cctx->iv);
	cctx->iv = NULL;
free_priv:
	if (tx) {
		kfree(ctx->priv_ctx_tx);
		ctx->priv_ctx_tx = NULL;
	} else {
		kfree(ctx->priv_ctx_rx);
		ctx->priv_ctx_rx = NULL;
	}
out:
	return rc;
}
