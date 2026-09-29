package com.wdtt.plus.ui

/** Read-only checks shared by installation, diagnostics and the WARP watchdog. */
internal fun outboundProbeFunctions(): String = """
    wdtt_probe_ipv4() {
      printf '%s\n' "${'$'}1" | awk -F. '
        NR != 1 || NF != 4 { exit 1 }
        { for (i=1; i<=4; i++) if (${'$'}i !~ /^[0-9]+$/ || ${'$'}i > 255) exit 1 }
      '
    }
    wdtt_routed_https() (
      source_ip="${'$'}1"
      expected_iface="${'$'}2"
      url="${'$'}3"
      [ -n "${'$'}source_ip" ] && [ -n "${'$'}expected_iface" ] || return 1
      host="${'$'}{url#https://}"
      host="${'$'}{host%%/*}"
      destination="${'$'}(getent ahostsv4 "${'$'}host" 2>/dev/null | awk '{print ${'$'}1; exit}')"
      wdtt_probe_ipv4 "${'$'}destination" || return 1
      route="${'$'}(ip -4 route get "${'$'}destination" from "${'$'}source_ip" 2>/dev/null)" || return 1
      printf '%s\n' "${'$'}route" | awk -v expected="${'$'}expected_iface" '
        { for (i=1; i<NF; i++) if (${'$'}i == "dev" && ${'$'}(i+1) == expected) found=1 }
        END { exit found ? 0 : 1 }
      ' || return 1
      # Pin the same destination whose route was checked. Do not use curlrc/env proxies.
      response="${'$'}(curl -q --proxy '' --noproxy '*' --interface "${'$'}source_ip" \
        --resolve "${'$'}host:443:${'$'}destination" -4fsS --connect-timeout 4 --max-time 10 \
        "${'$'}url" 2>/dev/null)" || return 1
      [ -n "${'$'}response" ] || return 1
      printf '%s\n' "${'$'}response"
    )
    wdtt_routed_public_ip() (
      for url in https://api.ipify.org https://checkip.amazonaws.com; do
        result="${'$'}(wdtt_routed_https "${'$'}1" "${'$'}2" "${'$'}url")" || continue
        if wdtt_probe_ipv4 "${'$'}result"; then printf '%s\n' "${'$'}result"; return 0; fi
      done
      return 1
    )
""".trimIndent()
