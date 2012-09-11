package togos.blob;

import togos.blob.util.BlobUtil;

public class SimpleByteChunk implements ByteChunk
{
	public static final byte[] EMPTY_BYTE_ARRAY = new byte[0];
	public static final SimpleByteChunk EMPTY = new SimpleByteChunk(EMPTY_BYTE_ARRAY,0,0);
	
	/** @return a new SimpleByteChunk referencing a new buffer. */
	public static SimpleByteChunk copyOf( byte[] buf, int offset, int size ) {
		byte[] bu2 = new byte[size];
		SimpleByteChunk sbc = new SimpleByteChunk( bu2, 0, size );
		for( size = size-1; size >= 0; --size ) {
			bu2[size] = buf[offset+size];
		}
		return sbc;
	}
	
	/** @return a new SimpleByteChunk referencing a new buffer. */
	public static SimpleByteChunk copyOf( ByteChunk c ) {
		return copyOf( c.getBuffer(), c.getOffset(), c.getSize() );
	}
	
	public final byte[] buffer;
	public final int offset;
	public final int size;
	
	public SimpleByteChunk( byte[] buf, int offset, int size ) {
		this.buffer = buf;
		this.offset = offset;
		this.size = size;
	}
	
	public SimpleByteChunk( byte[] buf ) {
		this( buf, 0, buf.length );
	}
	
	public byte[] getBuffer() { return buffer; }
	public int getOffset() { return offset; }
	public int getSize() { return size; }
	
	public int hashCode() {
		return BlobUtil.hashCode(buffer, offset, size);
	}
	
	public boolean equals( Object o ) {
		if( o instanceof ByteChunk ) return BlobUtil.equals( this, (ByteChunk)o );
		return false;
	}
	
	
	public String toString() {
		// Comment out for general use; this is to help debug while
		// unit-testing when I know these things are all string-able.
		return BlobUtil.string(buffer, offset, size);
	}
	
}
