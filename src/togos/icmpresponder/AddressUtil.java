package togos.icmpresponder;

import togos.blob.ByteChunk;

class AddressUtil
{
	public static String formatIp6Address( byte[] addy, int offset ) {
		int[] parts = new int[8];
		for( int i=0; i<8; ++i ) {
			parts[i] = ((addy[offset+i*2]&0xFF) << 8) | (addy[offset+i*2+1]&0xFF);
		}
		String rez = "";
		for( int i=0; i<8; ++i ) {
			if( i > 0 ) rez += ":";
			rez += Integer.toHexString(parts[i]);
		}
		return rez;
	}
	
	public static String formatIp6Address( ByteChunk addy ) {
		return formatIp6Address( addy.getBuffer(), addy.getOffset() );
	}
}