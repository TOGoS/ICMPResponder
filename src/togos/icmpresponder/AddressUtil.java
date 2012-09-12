package togos.icmpresponder;

import togos.blob.ByteChunk;

public class AddressUtil
{
	static class AddressFormatException extends RuntimeException {
		private static final long serialVersionUID = 1L;
		public AddressFormatException( String m, String input ) {
			super(m+"; "+input);
		}
	}
	
	public static String formatIp6Address( byte[] addy, int offset ) {
		assert( offset >= 0 );
		assert( offset + 16 <= addy.length );
		
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
	
	public static byte[] parseIp4Address( String str ) throws AddressFormatException {
		String[] parts = str.split("\\.");
		if( parts.length != 4 ) {
			throw new AddressFormatException("IP4 address does not have 4 parts", str);
		}
		byte[] addy = new byte[4];
		for( int i=0; i<4; ++i ) {
			int j = Integer.parseInt(parts[i]);
			if( j > 255 ) throw new AddressFormatException("IP4 address component ("+j+") > 255", str);
			if( j < 0   ) throw new AddressFormatException("IP4 address component ("+j+") < 0", str);
			addy[i] = (byte)j;
		}
		return addy;
	}
}