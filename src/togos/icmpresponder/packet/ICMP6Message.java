package togos.icmpresponder.packet;

import togos.blob.SimpleByteChunk;
import togos.icmpresponder.ByteUtil;

public class ICMP6Message extends SimpleByteChunk
{
	public static final int ICMP6_HEADER_SIZE = 4;
	
	public final IPPacket ipPacket;
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
	
	public int getPayloadOffset() { return offset + 8; }
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
}
