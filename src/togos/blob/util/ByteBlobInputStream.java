package togos.blob.util;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;

import togos.blob.ByteChunk;

public class ByteBlobInputStream extends InputStream
{
	Iterator chunks;
	ByteChunk currentChunk;
	int currentChunkPosition;
	boolean ended;

	public ByteBlobInputStream( Iterator chunks ) {
		this.chunks = chunks;
	}
	
	/**
	 * Returns a chunk from which at least 1 byte that can be read
	 * starting at the current position, or null if there is no data left. 
	 */
	protected ByteChunk getCurrentChunk() {
		while( !ended && (currentChunk == null || currentChunkPosition >= currentChunk.getSize()) ) {
			if( chunks.hasNext() ) {
				currentChunk = (ByteChunk)chunks.next();
				currentChunkPosition = 0;
			} else {
				ended = true;
			}
		}
		if( ended ) return null;
		return currentChunk;
	}
	
	public int read() {
		ByteChunk c = getCurrentChunk();
		if( c == null ) return -1;
		return c.getBuffer()[c.getOffset()+currentChunkPosition++] & 0xFF;
	}
	
	public int available() {
		if( ended ) return 0;
		ByteChunk c = currentChunk;
		if( c == null ) return 0;
		return c.getSize() - currentChunkPosition;
	}
	
	public int read(byte[] ob, int off, int len) {
		if( len == 0 ) return 0;
		
		ByteChunk c = getCurrentChunk();
		if( c == null ) return -1;
		
		if( currentChunkPosition + len > c.getSize() ) {
			len = c.getSize() - currentChunkPosition;
		}
		byte[] ib = c.getBuffer();
		int ip = c.getOffset()+currentChunkPosition;
		int op = off;
		for( int i=0; i<len; ++i, ++op, ++ip ) {
			ob[op] = ib[ip];
		}
		currentChunkPosition += len;
		return len;
	}
	
	public void close() throws IOException {
		if( chunks instanceof Closeable ) {
			((Closeable)chunks).close(); 
		}
	}
}
