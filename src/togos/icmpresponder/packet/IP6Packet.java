package togos.icmpresponder.packet;

import togos.icmpresponder.ByteUtil;
import togos.icmpresponder.InvalidIPPacket;

public class IP6Packet extends IPPacket
{
	public static final int IP6_HEADER_SIZE = 40;
	public static final int IP6_ADDRESS_SIZE = 16;
	
	protected int payloadSize;
	
	public IP6Packet( byte[] buffer, int offset, int size, int payloadSize ) {
		super( buffer, offset, size );
		this.payloadSize = payloadSize;
	}
	
	@Override public int getIpVersion() { return 6; }
	@Override public int getSourceAddressOffset() { return offset + 8; }
	@Override public int getSourceAddressSize() { return IP6_ADDRESS_SIZE; }
	@Override public int getDestinationAddressOffset() { return offset + 24; }
	@Override public int getDestinationAddressSize() { return IP6_ADDRESS_SIZE; }
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
	
	public static IP6Packet create(
		byte[] sourceAddressBuffer, int sourceAddressOffset,
		byte[] destAddressBuffer, int destAddressOffset,
		int payloadProtocolNumber, int hopLimit, int payloadSize
	) {
		int totalSize = IP6_HEADER_SIZE + payloadSize;
		byte[] packetBuffer = new byte[totalSize];
		packetBuffer[0] = 6 << 4;
		// some other stuff would go in here
		ByteUtil.encodeInt16( payloadSize, packetBuffer, 4 );
		packetBuffer[6] = (byte)payloadProtocolNumber;
		packetBuffer[7] = (byte)hopLimit;
		ByteUtil.copy( sourceAddressBuffer, sourceAddressOffset, packetBuffer, 8, IP6_ADDRESS_SIZE );
		ByteUtil.copy( destAddressBuffer, destAddressOffset, packetBuffer, 24, IP6_ADDRESS_SIZE );
		
		return new IP6Packet( packetBuffer, 0, packetBuffer.length, payloadSize );
	}
}
