package com.wdtt.plus.ui

/** Keep the error marker and its details even after a long install/progress log. */
internal fun rootScriptErrorExcerpt(output: String): String {
    val marker = Regex("(?m)^WDTT_ERROR=").findAll(output).lastOrNull()
    return if (marker != null) output.substring(marker.range.first).take(1600)
    else output.takeLast(1600)
}

internal fun externalProxyFailureMessage(output: String): String {
    val code = Regex("(?m)^WDTT_PROXY_CURL_EXIT=(\\d+)").find(output)?.groupValues?.get(1)?.toIntOrNull()
    val reason = when (code) {
        5, 6 -> "Сервер не смог определить адрес проверочного сайта через DNS."
        7 -> "Не удалось установить TCP-соединение через перенаправление."
        22 -> "Проверочные сайты вернули ошибку HTTP."
        28 -> "Истекло время ожидания ответа через прокси."
        35, 60 -> "Не прошла проверка защищённого HTTPS-соединения."
        45 -> "Не удалось отправить проверку с адреса интерфейса WDTT."
        0 -> "Проверочные сайты не вернули корректный IPv4-адрес."
        else -> "Не удалось получить ответ проверочного сайта через прокси."
    }
    return "$reason Включение внешнего TCP-прокси отменено, восстановлен прямой выход WDTT. " +
        "Кнопка «Проверить» проверяет сам прокси отдельно от перенаправления через redsocks."
}

internal fun externalProxyProbeFunctions(): String = """
    wdtt_valid_proxy_test_ip() {
      printf '%s\n' "${'$'}1" | awk -F. '
        NR != 1 || NF != 4 { exit 1 }
        { for (i = 1; i <= 4; i++) if (${'$'}i !~ /^[0-9]+$/ || ${'$'}i > 255) exit 1 }
      '
    }
    wdtt_test_redsocks_path() {
      proxy_ip="${'$'}1"
      systemctl is-active --quiet wdtt-redsocks || { echo WDTT_ERROR=external_proxy_service_inactive; return 1; }
      command -v curl >/dev/null 2>&1 || { echo WDTT_ERROR=curl_not_installed; return 1; }
      test_source="${'$'}(wdtt_test_source)"
      [ -n "${'$'}test_source" ] || { echo WDTT_ERROR=wdtt_iface_not_found; return 1; }
      wdtt_cleanup_proxy_test
      WDTT_PROXY_TEST_SOURCE="${'$'}test_source"
      if ! iptables -I INPUT -i lo -s "${'$'}test_source" -d 127.0.0.1 -p tcp --dport 12345 -m comment --comment WDTT_PROXY_TEST -j ACCEPT ||
         ! iptables -t nat -N WDTT_PROXY_TEST ||
         ! wdtt_proxy_reserved_returns WDTT_PROXY_TEST "${'$'}proxy_ip" ||
         ! iptables -t nat -A WDTT_PROXY_TEST -p tcp -j REDIRECT --to-ports 12345 ||
         ! iptables -t nat -I OUTPUT -s "${'$'}test_source" -p tcp -j WDTT_PROXY_TEST; then
        wdtt_cleanup_proxy_test
        echo WDTT_ERROR=external_proxy_test_rule_failed
        return 1
      fi
      test_error_file="${'$'}(mktemp /tmp/wdtt-proxy-check.XXXXXX)" || {
        wdtt_cleanup_proxy_test
        echo WDTT_ERROR=external_proxy_test_temp_failed
        return 1
      }
      test_ok=0
      test_code=0
      for test_url in https://api.ipify.org https://checkip.amazonaws.com; do
        test_code=0
        # Ignore curlrc and environment proxies: only our transparent route is under test.
        test_ip="${'$'}(curl -q --proxy '' --noproxy '*' --interface "${'$'}test_source" \
          -4fsS --connect-timeout 5 --max-time 12 "${'$'}test_url" 2>"${'$'}test_error_file")" || test_code=${'$'}?
        if [ "${'$'}test_code" = 0 ] && wdtt_valid_proxy_test_ip "${'$'}test_ip"; then
          test_ok=1
          break
        fi
      done
      # A successful direct request must never masquerade as a working transparent proxy.
      test_packets="${'$'}(iptables -t nat -L WDTT_PROXY_TEST -n -v -x 2>/dev/null |
        awk '${'$'}3 == "REDIRECT" { total += ${'$'}1 } END { print total + 0 }')"
      wdtt_cleanup_proxy_test
      rm -f "${'$'}test_error_file"
      if [ "${'$'}test_ok" != 1 ]; then
        echo WDTT_ERROR=external_proxy_apply_failed
        echo "WDTT_PROXY_CURL_EXIT=${'$'}test_code"
        return 1
      fi
      if [ "${'$'}test_packets" -eq 0 ]; then
        echo WDTT_ERROR=external_proxy_test_not_redirected
        return 1
      fi
      echo "Проверка перенаправления через redsocks успешна. IP через прокси: ${'$'}test_ip"
    }
""".trimIndent()
