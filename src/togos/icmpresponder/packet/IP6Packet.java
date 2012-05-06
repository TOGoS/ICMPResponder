package togos.icmpresponder.packet;

import togos.icmpresponder.ByteUtil;
import togos.icmpresponder.InvalidIPPacket;

public class IP6Packet extends IPPacket
{
	public static final int IP6_HEADER_SIZE = 40;
	
	protected int payloadSize;
	
	public IP6Packet( byte[] buffer, int offset, int size, int payloadSize ) {
		super( buffer, offset, size );
		this.payloadSize = payloadSize;
	}
	
	@Override public int getIpVersion() { return 6; }
	@Override public int getSourceAddressOffset() { return offset + 8; }
	@Override public int getSourceAddressSize() { return 16; }
	@Override public int getDestinationAddressOffset() { return offset + 24; }
	@Override public int getDestinationAddressSize() { return 16; }
	@Override public int getPayloadProtocolNumber() { return buffer[offset+6] & 0xFF; }
	@Override public int getHopLimit() { return buffer[offset+7] & 0xFF; }
	@Override public int getPayloadOffset() { return 40; }
	@Override public int getPayloadSize() { return payloadSize; }
	
	public static IPPacket parse( byte[] buffer, int offset, int size ) {
		if( size < IP6_HEADER_SIZE ) return new InvalidIPPacket(buffer, offset, size, "Supposed IP6 packet not large enough for IP6 header");
		int payloadSize = ByteUtil.decodeUInt16( buffer, offset + 4 );
		if( payloadSize < 0 ) return new InvalidIPPacket(buffer, offset, size, "IP6 payload length < 0");
		if( payloadSize + IP6_HEADER_SIZE > size ) return new InvalidIPPacket(buffer, offset, size, "IP6 payload length too large for packet");
		// Ignore version and flow label for now
		return new IP6Packet( buffer, offset, size, payloadSize );
	}
}
