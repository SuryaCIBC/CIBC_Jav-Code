package com.example.xmlsign;

import org.apache.commons.net.ntp.NTPUDPClient;
import org.apache.commons.net.ntp.TimeInfo;

import java.net.InetAddress;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Date;

public final class BarbadosTimeUtil {

	private static final String DEFAULT_NTP = "bb.pool.ntp.org";
	private static final ZoneId BARBADOS_ZONE = ZoneId.of("America/Barbados");
	private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-ddXXX");

	private BarbadosTimeUtil() {
	}

	/**
	 * Returns Barbados time (America/Barbados) from NTP server as "yyyy-MM-ddXXX"
	 * e.g., "2026-02-26-04:00". Falls back to system clock if NTP fails.
	 */
	public static String getBarbadosDateFromNtp() {
		return getBarbadosDateFromNtp(DEFAULT_NTP, 3000);
	}

	/**
	 * Returns Barbados time (America/Barbados) from the given NTP server as
	 * "yyyy-MM-ddXXX" with a configurable timeout in milliseconds. Falls back to
	 * system clock on failure.
	 *
	 * @param ntpServer e.g., "bb.pool.ntp.org"
	 * @param timeoutMs socket timeout in milliseconds (e.g., 3000)
	 * @return formatted string like "yyyy-MM-dd-04:00"
	 */
	public static String getBarbadosDateFromNtp(String ntpServer, int timeoutMs) {
		Instant instant = fetchNtpInstantOrNow(ntpServer, timeoutMs);
		ZonedDateTime bbTime = instant.atZone(BARBADOS_ZONE);
		return bbTime.format(FMT);
	}

	public static Instant getNtpInstantOrNow() {
		return getNtpInstantOrNow("bb.pool.ntp.org", 3000);
	}

	public static Instant getNtpInstantOrNow(String ntpServer, int timeoutMs) {
		org.apache.commons.net.ntp.NTPUDPClient client = new org.apache.commons.net.ntp.NTPUDPClient();
		client.setDefaultTimeout(timeoutMs);
		try {
			client.open();
			org.apache.commons.net.ntp.TimeInfo info = client.getTime(java.net.InetAddress.getByName(ntpServer));
			java.util.Date ntpDate = info.getMessage().getTransmitTimeStamp().getDate();
			return ntpDate.toInstant();
		} catch (Exception ex) {
			return java.time.Instant.now(); // safe fallback
		} finally {
			client.close();
		}
	}

	/**
	 * Returns current Instant from NTP, or system Instant on any failure.
	 */
	private static Instant fetchNtpInstantOrNow(String ntpServer, int timeoutMs) {
		NTPUDPClient client = new NTPUDPClient();
		client.setDefaultTimeout(timeoutMs);
		try {
			client.open();
			TimeInfo info = client.getTime(InetAddress.getByName(ntpServer));
			// Use the server transmit timestamp as the authoritative current time
			Date ntpDate = info.getMessage().getTransmitTimeStamp().getDate();
			return ntpDate.toInstant();
		} catch (Exception ex) {
			// Fallback to system time if NTP unavailable/timeouts/DNS issues
			return Instant.now();
		} finally {
			client.close();
		}
	}

	// Example usage
	public static void main(String[] args) {
		String formatted = BarbadosTimeUtil.getBarbadosDateFromNtp();
		System.out.println(formatted); // e.g., 2026-02-26-04:00
	}
}
