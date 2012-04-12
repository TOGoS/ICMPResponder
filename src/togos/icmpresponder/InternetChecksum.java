package togos.icmpresponder;

// Based on code from
// http://stackoverflow.com/questions/4113890/how-to-calculate-the-internet-checksum-from-a-byte-in-java

public class InternetChecksum
{
	/**
	 * Version by Gary Rowe
	 * 
	 * Calculate the Internet Checksum of a buffer (RFC 1071 -
	 * http://www.faqs.org/rfcs/rfc1071.html) Algorithm is 1) apply a 16-bit 1's
	 * complement sum over all octets (adjacent 8-bit pairs [A,B], final odd
	 * length is [A,0]) 2) apply 1's complement to this final sum
	 * 
	 * Notes: 1's complement is bitwise NOT of positive value. Ensure that any
	 * carry bits are added back to avoid off-by-one errors
	 * 
	 * 
	 * @param buf
	 *            The message
	 * @return The checksum
	 */
	public static long oldChecksum(byte[] buf) {
		int length = buf.length;
		int i = 0;

		long sum = 0;
		long data;

		// Handle all pairs
		while (length > 1) {
			// Corrected to include @Andy's edits and various comments on Stack
			// Overflow
			data = (((buf[i] << 8) & 0xFF00) | ((buf[i + 1]) & 0xFF));
			sum += data;
			// 1's complement carry bit correction in 16-bits (detecting sign
			// extension)
			if ((sum & 0xFFFF0000) > 0) {
				sum = sum & 0xFFFF;
				sum += 1;
			}

			i += 2;
			length -= 2;
		}

		// Handle remaining byte in odd length buffers
		if (length > 0) {
			// Corrected to include @Andy's edits and various comments on Stack
			// Overflow
			sum += (buf[i] << 8 & 0xFF00);
			// 1's complement carry bit correction in 16-bits (detecting sign
			// extension)
			if ((sum & 0xFFFF0000) > 0) {
				sum = sum & 0xFFFF;
				sum += 1;
			}
		}

		// Final 1's complement value correction to 16-bits
		sum = ~sum;
		sum = sum & 0xFFFF;
		return sum;
	}
	
	/**
	 * Shorter version by James Hughes
	 */
	public static long checksum(byte[] buf, int length) {
	    int i = 0;
	    long sum = 0;
	    while (length > 0) {
	        sum += (buf[i++]&0xff) << 8;
	        if ((--length)==0) break;
	        sum += (buf[i++]&0xff);
	        --length;
	    }
	    return (~((sum & 0xFFFF)+(sum >> 16)))&0xFFFF;
	}
	
	public static long checksum( byte[] buf ) {
		return checksum( buf, buf.length );
	}
}
