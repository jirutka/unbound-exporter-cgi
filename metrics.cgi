#!/bin/sh
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Jakub Jirutka <jakub@jirutka.cz>
# Website: https://github.com/jirutka/unbound-exporter-cgi/
# Version: 1.0.0
#
# A CGI script to expose Unbound statistics as Prometheus-style metrics.
#
# The metrics are the same as produced by
# https://github.com/letsencrypt/unbound_exporter, except the "thread" label
# which is not used here.

# unbound-control is usually installed in /usr/sbin, but some CGI servers
# (thttpd) exports PATH without /sbin directories.
export PATH="$PATH:/usr/sbin"

# Options to pass to unbound-control.
readonly CONTROL_OPTS=''

readonly AWK_SCRIPT='
BEGIN {
	FS="=";
	hist_count = 0
}
/^num\.answer\.rcode\.\w+=/ {
	split($1, parts, /[.]/)
	if (!skip_comment["unbound_answer_rcodes_total"]) {
		print "# HELP unbound_answer_rcodes_total Total number of answers to queries, from cache or from recursion, by response code."
		print "# TYPE unbound_answer_rcodes_total counter"
		skip_comment["unbound_answer_rcodes_total"]=1
	}
	printf "unbound_answer_rcodes_total{rcode=\"%s\"} %s\n", parts[4], $2
}
/^num\.answer\.bogus=/ {
	print "# HELP unbound_answers_bogus Total number of answers that were bogus."
	print "# TYPE unbound_answers_bogus counter"
	printf "unbound_answers_bogus %s\n", $2
}
/^num\.answer\.secure=/ {
	print "# HELP unbound_answers_secure_total Total number of answers that were secure."
	print "# TYPE unbound_answers_secure_total counter"
	printf "unbound_answers_secure_total %s\n", $2
}
/^total\.num\.cachehits=/ {
	print "# HELP unbound_cache_hits_total Total number of queries that were successfully answered using a cache lookup."
	print "# TYPE unbound_cache_hits_total counter"
	printf "unbound_cache_hits_total %s\n", $2
}
/^total\.num\.cachemiss=/ {
	print "# HELP unbound_cache_misses_total Total number of cache queries that needed recursive processing."
	print "# TYPE unbound_cache_misses_total counter"
	printf "unbound_cache_misses_total %s\n", $2
}
/^total\.num\.queries_cookie_client=/ {
	print "# HELP unbound_queries_cookie_client_total Total number of queries with a client cookie."
	print "# TYPE unbound_queries_cookie_client_total counter"
	printf "unbound_queries_cookie_client_total %s\n", $2
}
/^total\.num\.queries_invalid_client=/ {
	print "# HELP unbound_queries_cookie_invalid_total Total number of queries with a invalid cookie."
	print "# TYPE unbound_queries_cookie_invalid_total counter"
	printf "unbound_queries_cookie_invalid_total %s\n", $2
}
/^total\.num\.queries_cookie_valid=/ {
	print "# HELP unbound_queries_cookie_valid_total Total number of queries with a valid cookie."
	print "# TYPE unbound_queries_cookie_valid_total counter"
	printf "unbound_queries_cookie_valid_total %s\n", $2
}
/^mem\.cache\.\w+=/ {
	split($1, parts, /[.]/)
	if (!skip_comment["unbound_memory_caches_bytes"]) {
		print "# HELP unbound_memory_caches_bytes Memory in bytes in use by caches."
		print "# TYPE unbound_memory_caches_bytes gauge"
		skip_comment["unbound_memory_caches_bytes"]=1
	}
	printf "unbound_memory_caches_bytes{cache=\"%s\"} %s\n", parts[3], $2
}
/^mem\.mod\.\w+=/ {
	split($1, parts, /[.]/)
	if (!skip_comment["unbound_memory_modules_bytes"]) {
		print "# HELP unbound_memory_modules_bytes Memory in bytes in use by modules."
		print "# TYPE unbound_memory_modules_bytes gauge"
		skip_comment["unbound_memory_modules_bytes"]=1
	}
	printf "unbound_memory_modules_bytes{module=\"%s\"} %s\n", parts[3], $2
}
/^mem\.total\.sbrk=/ {
	print "# HELP unbound_memory_sbrk_bytes Memory in bytes allocated through sbrk."
	print "# TYPE unbound_memory_sbrk_bytes gauge"
	printf "unbound_memory_sbrk_bytes %s\n", $2
}
/^total\.num\.prefetch=/ {
	print "# HELP unbound_prefetches_total Total number of cache prefetches performed."
	print "# TYPE unbound_prefetches_total counter"
	printf "unbound_prefetches_total %s\n", $2
}
/^total\.num\.queries=/ {
	print "# HELP unbound_queries_total Total number of queries received."
	print "# TYPE unbound_queries_total counter"
	printf "unbound_queries_total %s\n", $2
}
/^total\.num\.expired=/ {
	print "# HELP unbound_expired_total Total number of expired entries served."
	print "# TYPE unbound_expired_total counter"
	printf "unbound_expired_total %s\n", $2
}
/^num\.query\.class\.\w+=/ {
	split($1, parts, /[.]/)
	if (!skip_comment["unbound_query_classes_total"]) {
		print "# HELP unbound_query_classes_total Total number of queries with a given query class."
		print "# TYPE unbound_query_classes_total counter"
		skip_comment["unbound_query_classes_total"]=1
	}
	printf "unbound_query_classes_total{class=\"%s\"} %s\n", parts[4], $2
}
/^num\.query\.flags\.\w+=/ {
	split($1, parts, /[.]/)
	if (!skip_comment["unbound_query_flags_total"]) {
		print "# HELP unbound_query_flags_total Total number of queries that had a given flag set in the header."
		print "# TYPE unbound_query_flags_total counter"
		skip_comment["unbound_query_flags_total"]=1
	}
	printf "unbound_query_flags_total{flag=\"%s\"} %s\n", parts[4], $2
}
/^num\.query\.ipv6=/ {
	print "# HELP unbound_query_ipv6_total Total number of queries that were made using IPv6 towards the Unbound server."
	print "# TYPE unbound_query_ipv6_total counter"
	printf "unbound_query_ipv6_total %s\n", $2
}
/^num\.query\.opcode\.\w+=/ {
	split($1, parts, /[.]/)
	if (!skip_comment["unbound_query_opcodes_total"]) {
		print "# HELP unbound_query_opcodes_total Total number of queries with a given query opcode."
		print "# TYPE unbound_query_opcodes_total counter"
		skip_comment["unbound_query_opcodes_total"]=1
	}
	printf "unbound_query_opcodes_total{opcode=\"%s\"} %s\n", parts[4], $2
}
/^num\.query\.edns\.DO=/ {
	print "# HELP unbound_query_edns_DO_total Total number of queries that had an EDNS OPT record with the DO (DNSSEC OK) bit set present."
	print "# TYPE unbound_query_edns_DO_total counter"
	printf "unbound_query_edns_DO_total %s\n", $2
}
/^num\.query\.edns\.present=/ {
	print "# HELP unbound_query_edns_present_total Total number of queries that had an EDNS OPT record present."
	print "# TYPE unbound_query_edns_present_total counter"
	printf "unbound_query_edns_present_total %s\n", $2
}
/^num\.query\.tcp=/ {
	print "# HELP unbound_query_tcp_total Total number of queries that were made using TCP towards the Unbound server, including DoT and DoH queries."
	print "# TYPE unbound_query_tcp_total counter"
	printf "unbound_query_tcp_total %s\n", $2
}
/^num\.query\.tcpout=/ {
	print "# HELP unbound_query_tcpout_total Total number of queries that the Unbound server made using TCP outgoing towards other servers."
	print "# TYPE unbound_query_tcpout_total counter"
	printf "unbound_query_tcpout_total %s\n", $2
}
/^num\.query\.tls=/ {
	print "# HELP unbound_query_tls_total Total number of queries that were made using TCP TLS towards the Unbound server, including DoT and DoH queries."
	print "# TYPE unbound_query_tls_total counter"
	printf "unbound_query_tls_total %s\n", $2
}
/^num\.query\.tls\.resume=/ {
	print "# HELP unbound_query_tls_resume_total Total number of queries that were made using TCP TLS Resume towards the Unbound server."
	print "# TYPE unbound_query_tls_resume_total counter"
	printf "unbound_query_tls_resume_total %s\n", $2
}
/^num\.query\.https=/ {
	print "# HELP unbound_query_https_total Total number of DoH queries that were made towards the Unbound server."
	print "# TYPE unbound_query_https_total counter"
	printf "unbound_query_https_total %s\n", $2
}
/^num\.query\.type\.\w+=/ {
	split($1, parts, /[.]/)
	if (!skip_comment["unbound_query_types_total"]) {
		print "# HELP unbound_query_types_total Total number of queries with a given query type."
		print "# TYPE unbound_query_types_total counter"
		skip_comment["unbound_query_types_total"]=1
	}
	printf "unbound_query_types_total{type=\"%s\"} %s\n", parts[4], $2
}
/^num\.query\.udpout=/ {
	print "# HELP unbound_query_udpout_total Total number of queries that the Unbound server made using UDP outgoing towards￼other servers."
	print "# TYPE unbound_query_udpout_total counter"
	printf "unbound_query_udpout_total %s\n", $2
}
/^num\.query\.aggressive\.\w+=/ {
	split($1, parts, /[.]/)
	if (!skip_comment["unbound_query_aggressive_nsec"]) {
		print "# HELP unbound_query_aggressive_nsec Total number of queries that the Unbound server generated response using Aggressive NSEC."
		print "# TYPE unbound_query_aggressive_nsec counter"
		skip_comment["unbound_query_aggressive_nsec"]=1
	}
	printf "unbound_query_aggressive_nsec{rcode=\"%s\"} %s\n", parts[4], $2
}
/^total\.requestlist\.current\.all=/ {
	print "# HELP unbound_request_list_current_all Current size of the request list, including internally generated queries."
	print "# TYPE unbound_request_list_current_all gauge"
	printf "unbound_request_list_current_all %s\n", $2
}
/^total\.requestlist\.current\.user=/ {
	print "# HELP unbound_request_list_current_user Current size of the request list, only counting the requests from client queries."
	print "# TYPE unbound_request_list_current_user gauge"
	printf "unbound_request_list_current_user %s\n", $2
}
/^total\.requestlist\.exceeded=/ {
	print "# HELP unbound_request_list_exceeded_total Number of queries that were dropped because the request list was full."
	print "# TYPE unbound_request_list_exceeded_total counter"
	printf "unbound_request_list_exceeded_total %s\n", $2
}
/^total\.requestlist\.overwritten=/ {
	print "# HELP unbound_request_list_overwritten_total Total number of requests in the request list that were overwritten by newer entries."
	print "# TYPE unbound_request_list_overwritten_total counter"
	printf "unbound_request_list_overwritten_total %s\n", $2
}
/^total\.num\.recursivereplies=/ {
	print "# HELP unbound_recursive_replies_total Total number of replies sent to queries that needed recursive processing."
	print "# TYPE unbound_recursive_replies_total counter"
	printf "unbound_recursive_replies_total %s\n", $2
}
/^num\.rrset\.bogus=/ {
	print "# HELP unbound_rrset_bogus_total Total number of rrsets marked bogus by the validator."
	print "# TYPE unbound_rrset_bogus_total counter"
	printf "unbound_rrset_bogus_total %s\n", $2
}
/^rrset\.cache\.max_collisions=/ {
	print "# HELP unbound_rrset_cache_max_collisions_total Total number of rrset cache hashtable collisions."
	print "# TYPE unbound_rrset_cache_max_collisions_total counter"
	printf "unbound_rrset_cache_max_collisions_total %s\n", $2
}
/^time\.elapsed=/ {
	print "# HELP unbound_time_elapsed_seconds Time since last statistics printout in seconds."
	print "# TYPE unbound_time_elapsed_seconds counter"
	printf "unbound_time_elapsed_seconds %s\n", $2
}
/^time\.now=/ {
	print "# HELP unbound_time_now_seconds Current time in seconds since 1970."
	print "# TYPE unbound_time_now_seconds gauge"
	printf "unbound_time_now_seconds %s\n", $2
}
/^time\.up=/ {
	print "# HELP unbound_time_up_seconds_total Uptime since server boot in seconds."
	print "# TYPE unbound_time_up_seconds_total counter"
	printf "unbound_time_up_seconds_total %s\n", $2
}
/^unwanted\.queries=/ {
	print "# HELP unbound_unwanted_queries_total Total number of queries that were refused or dropped because they failed the access control settings."
	print "# TYPE unbound_unwanted_queries_total counter"
	printf "unbound_unwanted_queries_total %s\n", $2
}
/^unwanted\.replies=/ {
	print "# HELP unbound_unwanted_replies_total Total number of replies that were unwanted or unsolicited."
	print "# TYPE unbound_unwanted_replies_total counter"
	printf "unbound_unwanted_replies_total %s\n", $2
}
/^total\.recursion\.time\.avg=/ {
	print "# HELP unbound_recursion_time_seconds_avg Average time it took to answer queries that needed recursive processing (does not include in-cache requests)."
	print "# TYPE unbound_recursion_time_seconds_avg gauge"
	printf "unbound_recursion_time_seconds_avg %s\n", $2
	hist_avg = $2 + 0.0
}
/^total\.recursion\.time\.median=/ {
	print "# HELP unbound_recursion_time_seconds_median The median of the time it took to answer queries that needed recursive processing."
	print "# TYPE unbound_recursion_time_seconds_median gauge"
	printf "unbound_recursion_time_seconds_median %s\n", $2
}
/^msg\.cache\.count=/ {
	print "# HELP unbound_msg_cache_count The Number of Messages cached"
	print "# TYPE unbound_msg_cache_count gauge"
	printf "unbound_msg_cache_count %s\n", $2
}
/^msg\.cache\.max_collisions=/ {
	print "# HELP unbound_msg_cache_max_collisions_total Total number of msg cache hashtable collisions."
	print "# TYPE unbound_msg_cache_max_collisions_total counter"
	printf "unbound_msg_cache_max_collisions_total %s\n", $2
}
/^rrset\.cache\.count=/ {
	print "# HELP unbound_rrset_cache_count The Number of rrset cached"
	print "# TYPE unbound_rrset_cache_count gauge"
	printf "unbound_rrset_cache_count %s\n", $2
}
/^num\.rpz\.action\.rpz-[\w-]+=/ {
	split($1, parts, /[.]/)
	if (!skip_comment["unbound_rpz_action_count"]) {
		print "# HELP unbound_rpz_action_count Total number of triggered Response Policy Zone actions, by type."
		print "# TYPE unbound_rpz_action_count counter"
		skip_comment["unbound_rpz_action_count"]=1
	}
	printf "unbound_rpz_action_count{type=\"%s\"} %s\n", substr(parts[4], 5), $2
}
/^mem\.http\.\w+=/ {
	split($1, parts, /[.]/)
	if (!skip_comment["unbound_memory_doh_bytes"]) {
		print "# HELP unbound_memory_doh_bytes Memory used by DoH buffers, in bytes."
		print "# TYPE unbound_memory_doh_bytes gauge"
		skip_comment["unbound_memory_doh_bytes"]=1
	}
	printf "unbound_memory_doh_bytes{buffer=\"%s\"} %s\n", parts[3], $2
}
# We have to convert non-cumulative buckets to cumulative histogram that
# Prometheus expects. Fortunately, Unbound prints the buckets already sorted by
# the upper bound, so we can just cummulate the values.
/^histogram\.\d+\.\d+\.to\.\d+\.\d+=/ {
	split($1, parts, /[.]/)
	if (!skip_comment["unbound_response_time_seconds"]) {
		print "# HELP unbound_response_time_seconds Query response time in seconds."
		print "# TYPE unbound_response_time_seconds histogram"
		skip_comment["unbound_response_time_seconds"]=1
	}
	upbound = (parts[5] "." parts[6]) + 0.0
	hist_count += ($2 + 0)

	printf "unbound_response_time_seconds_bucket{le=\"%g\"} %d\n", upbound, hist_count
}
END {
	if (hist_count > 0 && hist_avg != "") {
		# Finish the histogram. Prometheus expects the last bucket "+Inf"
		# and also _count and _sum metrics.
		printf "unbound_response_time_seconds_bucket{le=\"+Inf\"} %d\n", hist_count
		printf "unbound_response_time_seconds_count %d\n", hist_count
		printf "unbound_response_time_seconds_sum %f\n", hist_avg * hist_count
	}

	print "# HELP unbound_up Whether scraping Unbound metrics was successful."
	print "# TYPE unbound_up gauge"
	print "unbound_up 1"
}
'

print_headers() {
	local status="$1"
	# If not running as a CGI script, don't print headers.
	[ "${GATEWAY_INTERFACE-}" ] || return

	echo "Status: $status"
	echo 'Content-Type: text/plain'
	echo ''
}

if [ "$REQUEST_METHOD" ] && [ "$REQUEST_METHOD" != 'GET' ]; then
	print_headers 405
	echo 'Only GET method is supported'

elif out="$(unbound-control $CONTROL_OPTS stats_noreset 2>&1)"; then
	print_headers 200
	printf '%s\n' "$out" | awk "$AWK_SCRIPT"
else
	print_headers 500
	printf '%s\n' "$out" | sed -E 's/^\[\d+\] unbound-control\[\d+:\d+] //'

	# If not running as a CGI script, exit with error code.
	[ "${GATEWAY_INTERFACE-}" ] || exit 1
fi

exit 0
