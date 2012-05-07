package togos.icmpresponder.packet;

import togos.blob.SimpleByteChunk;
import togos.icmpresponder.ByteUtil;
import togos.icmpresponder.InternetChecksum;

public class ICMP6Message extends SimpleByteChunk
{
	public static final int ICMP6_HEADER_SIZE = 4;
	public static final int ICMP6_PROTOCOL_NUMBER = 58;
	
	public IPPacket ipPacket;
	public final int icmpMessageType;
	public final int icmpMessageCode;
	public final int icmpChecksum;
	
	public ICMP6Message( byte[] buffer, int offset, int size, IPPacket p, int type, int code, int checksum ) {
		super( buffer, offset, size );
		this.ipPacket = p;
		this.icmpMessageType = type;
		this.icmpMessageCode = code;
		this.icmpChecksum = checksum;
	}
	
	public int getPayloadOffset() { return offset + ICMP6_HEADER_SIZE; }
	public int getPayloadSize() { return size > ICMP6_HEADER_SIZE ? size - ICMP6_HEADER_SIZE : 0; }
	
	public static ICMP6Message parse( IPPacket ipp ) {
		byte[] buffer = ipp.getBuffer();
		int offset = ipp.getPayloadOffset();
		int size = ipp.getPayloadSize();
		if( size < ICMP6_HEADER_SIZE ) {
			return new ICMP6Message( buffer, offset, size, ipp, 0, 0, 0 );
		} else {
			return new ICMP6Message( buffer, offset, size, ipp,
				buffer[offset] & 0xFF, buffer[offset+1] & 0xFF,
				ByteUtil.decodeUInt16(buffer, offset+2) );
		}
	}
	
	public static long calculateIcmp6Checksum( IP6Packet p ) {
		byte[] data = new byte[40+p.payloadSize];
		ByteUtil.copy( p.getBuffer(), p.getSourceAddressOffset()     , data,  0, 16 ); // Source address
		ByteUtil.copy( p.getBuffer(), p.getDestinationAddressOffset(), data, 16, 16 ); // Destination address
		ByteUtil.encodeInt32( p.payloadSize, data, 32 );
		ByteUtil.encodeInt32( p.getPayloadProtocolNumber(), data, 36 );
		ByteUtil.copy( p.getBuffer(), p.getPayloadOffset(), data, 40, p.payloadSize );
		return InternetChecksum.checksum( data );
	}
	
	public static ICMP6Message create(
		byte[] sourceAddressBuffer, int sourceAddressOffset,
		byte[] destAddressBuffer, int destAddressOffset,
		int hopLimit,
		int type, int code, byte[] payload, int payloadOffset, int payloadSize
	) {
		IP6Packet p = IP6Packet.create(
			sourceAddressBuffer, sourceAddressOffset,
			destAddressBuffer, destAddressOffset,
			ICMP6_PROTOCOL_NUMBER, hopLimit, ICMP6_HEADER_SIZE + payloadSize
		);
		p.buffer[IP6Packet.IP6_HEADER_SIZE + 0] = (byte)type;
		p.buffer[IP6Packet.IP6_HEADER_SIZE + 1] = (byte)code;
		for( int i=0; i<payloadSize; ++i ) {
			p.buffer[IP6Packet.IP6_HEADER_SIZE + ICMP6_HEADER_SIZE + i] = (byte)payload[payloadOffset + i];
		}
		int checksum = (int)calculateIcmp6Checksum(p);
		ByteUtil.encodeInt16( checksum, p.buffer, IP6Packet.IP6_HEADER_SIZE + 2);
		return new ICMP6Message( p.buffer, IP6Packet.IP6_ADDRESS_SIZE, payloadSize + 4, p, type, code, checksum);
	}
}
