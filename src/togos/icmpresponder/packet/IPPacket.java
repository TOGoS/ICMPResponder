package togos.icmpresponder.packet;

import togos.blob.ByteChunk;
import togos.blob.SimpleByteChunk;

public abstract class IPPacket extends SimpleByteChunk
{
	protected IPPacket( byte[] buffer, int offset, int size ) {
		super( buffer, offset, size );
	}
	
	public int getIpVersion() {
		return size < 1 ? 0 : (buffer[offset] >> 4) & 0xF;
	}
	
	public abstract ByteChunk getSourceAddress();
	public abstract ByteChunk getDestinationAddress();
	public abstract int getPayloadProtocolNumber(); // a.k.a. 'next header' in IP6
	public abstract int getHopLimit(); // a.k.a. TTL in IP4
	public abstract int getPayloadOffset();
	public abstract int getPayloadSize();
	
	public static IPPacket parse( byte[] buf, int offset, int size ) {
		if( size < 1 ) return new InvalidIPPacket( buf, offset, size );
		switch( (buf[offset] >> 4) & 0xF ) {
		//case( 4 ): return IP4Packet.parse( buf, offset, size );
		case( 6 ): return IP6Packet.parse( buf, offset, size );
		default: return new InvalidIPPacket( buf, offset, size );
		}
	}
}
