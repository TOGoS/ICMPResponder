package togos.icmpresponder.packet;

import togos.blob.ByteChunk;
import togos.blob.SimpleByteChunk;

public class InvalidIPPacket extends IPPacket
{
	protected String note;
	
	public InvalidIPPacket( byte[] buffer, int offset, int size, String note ) {
		super( buffer, offset, size );
		this.note = note;
	}
	
	public InvalidIPPacket( byte[] buffer, int offset, int size ) {
		this( buffer, offset, size, "Invalid IP packet" );
	}
	
	@Override public ByteChunk getSourceAddress() { return SimpleByteChunk.EMPTY; }
	@Override public ByteChunk getDestinationAddress() { return SimpleByteChunk.EMPTY; }
	@Override public int getPayloadProtocolNumber() { return 0; }
	@Override public int getHopLimit() { return 0; }
	@Override public int getPayloadOffset() { return 0; }
	@Override public int getPayloadSize() { return 0; }
}
