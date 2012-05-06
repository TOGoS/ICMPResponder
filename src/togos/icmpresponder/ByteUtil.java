package togos.icmpresponder;

import togos.blob.ByteChunk;

public class ByteUtil {
	public static void copy( byte[] source, int sourceOffset, byte[] dest, int destOffset, int length ) {
		while( length > 0 ) {
			dest[destOffset++] = source[sourceOffset++];
			--length;
		}
	}
	
	public static void copy( ByteChunk source, byte[] dest, int destOffset ) {
		copy( source.getBuffer(), source.getOffset(), dest, destOffset, source.getSize() );
	}
	
	public static final void encodeInt32( int value, byte[] dest, int destOffset ) {
		dest[destOffset+0] = (byte)(value >> 24);
		dest[destOffset+1] = (byte)(value >> 16);
		dest[destOffset+2] = (byte)(value >>  8);
		dest[destOffset+3] = (byte)(value >>  0);
	}
	
	public static int decodeInt32( byte[] buffer, int offset ) {
		return
			((buffer[offset + 0]&0xFF) << 24) |
			((buffer[offset + 1]&0xFF) << 16) |
			((buffer[offset + 2]&0xFF) <<  8) |
			((buffer[offset + 3]&0xFF) <<  0);
	}
	
	public static void encodeInt16( int value, byte[] buffer, int offset ) {
		buffer[offset+0] = (byte)(value >> 8);
		buffer[offset+1] = (byte)(value >> 0);
	}
	
	public static int decodeUInt16( byte[] buffer, int offset ) {
		return
			((buffer[offset + 0]&0xFF) << 8) |
			((buffer[offset + 1]&0xFF) << 0);
	}
	
	//// Functions for getting values but doing bounds-checking first ////
	
	/**
	 * Ensures that a buffer of length bufferSize can contain a sub-buffer
	 * of length valueSize at valueOffset. 
	 */
	protected static void ensureRoom( int bufferSize, int valueOffset, int valueSize, String role ) {
		if( valueOffset < 0 ) {
			throw new IndexOutOfBoundsException( "Cannot read/write "+role+" ("+valueSize+" bytes at "+valueOffset+") because the offset is < 0!" );
		}
		if( valueOffset+valueSize > bufferSize ) {
			throw new IndexOutOfBoundsException( "Cannot read/write "+role+" ("+valueSize+" bytes at "+valueOffset+") because it is outside of allocated memory ("+bufferSize+" bytes)" );
		}
	}
}
