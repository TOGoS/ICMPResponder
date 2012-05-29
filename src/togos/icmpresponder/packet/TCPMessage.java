package togos.icmpresponder.packet;

import togos.blob.SimpleByteChunk;
import togos.icmpresponder.ByteUtil;
import togos.icmpresponder.InternetChecksum;

public class TCPMessage extends SimpleByteChunk
{
	public static final int TCP_PROTOCOL_NUMBER = 6;
	public static final int TCP_HEADER_SIZE = 20; // Assuming no options
	
	public IPPacket ipPacket;
	public boolean wellFormed;
	public String note;
	
	public int sourcePort;
	public int destPort;
	public int sequenceNumber;
	public int ackNumber;
	public int flags;
	public int windowSize;
	public int checksum;
	
	public int optionsOffset = 0;
	public int optionsSize = 0;
	public int payloadOffset = 0;
	public int payloadSize = 0;
	
	public TCPMessage( byte[] data, int offset, int size, IPPacket p, String note ) {
		super( data, offset, size );
		this.ipPacket = p;
		this.wellFormed = false;
		this.note = note;
	}
	
	public TCPMessage( byte[] data, int offset, int size, IPPacket p ) {
		super( data, offset, size );
		this.ipPacket = p;
	};
	
	public TCPMessage( IPPacket p ) {
		this( p.getBuffer(), p.getPayloadOffset(), p.getPayloadSize(), p );
	}
	
	/**
	 * Under normal circumstances this should return the same thing
	 * as ICMP6Message.calculateIcmp6Checksum( m.ipPacket )
	 * 
	 * It is here as sort of a double-check for my own code and to
	 * make sure packets are properly formed.
	 */
	public static int calculateChecksum( TCPMessage m ) {
		byte[] checksumBuffer = new byte[60 + m.optionsSize + m.payloadSize];
		// Not yet implemented for IP4 packets
		IP6Packet ip6p = (IP6Packet)m.ipPacket;
		ByteUtil.copy( ip6p.getBuffer(), ip6p.getSourceAddressOffset()       , checksumBuffer,  0, 16 );
		ByteUtil.copy( ip6p.getBuffer(), ip6p.getDestinationAddressOffset()  , checksumBuffer, 16, 16 );
		ByteUtil.encodeInt32( TCP_HEADER_SIZE + m.optionsSize + m.payloadSize, checksumBuffer,     32 ); // 'TCP Length'
		ByteUtil.encodeInt32( TCP_PROTOCOL_NUMBER, checksumBuffer, 36 ); // 'next header'
		
		// A simpler way (what ICMP6Message.calculateIcmp6Checksum( m.ipPacket ) would do):
		// ByteUtil.copy( m.getBuffer(), m.getOffset(), checksumBuffer, 40, m.getSize() );
		
		ByteUtil.copy( m.getBuffer(), m.getOffset(), checksumBuffer, 40, 20 ); // src/dest port, seq/ack num, falgs, windowSize, checksum, and urgent pointer
		ByteUtil.copy( m.getBuffer(), m.optionsOffset, checksumBuffer, 60, m.optionsSize );
		ByteUtil.copy( m.getBuffer(), m.payloadOffset, checksumBuffer, 60 + m.optionsSize, m.payloadSize );
		
		return (int)InternetChecksum.checksum(checksumBuffer);
	}
	
	public static TCPMessage createV6(
		byte[] sourceAddressBuffer, int sourceAddressOffset, int sourcePort,
		byte[] destAddressBuffer, int destAddressOffset, int destPort,
		int seqNum, int ackNum, int flags, int windowSize,
		byte[] payloadBuffer, int payloadOffset, int payloadSize
	) {
		IP6Packet p = IP6Packet.create(
			sourceAddressBuffer, sourceAddressOffset,
			destAddressBuffer, destAddressOffset,
			TCP_PROTOCOL_NUMBER, 255, TCP_HEADER_SIZE + payloadSize
		);
		byte[] data = p.getBuffer();
		int offset = p.getPayloadOffset();
		
		ByteUtil.encodeInt16( sourcePort, data, offset+0 );
		ByteUtil.encodeInt16( destPort, data, offset+2 );
		ByteUtil.encodeInt32( seqNum, data, offset+4 );
		ByteUtil.encodeInt32( ackNum, data, offset+8 );
		
		int dataOffsetWords = 5; // i.e. 20 bytes
		int falgs = (dataOffsetWords << 12) | (flags & 0x1F);
		ByteUtil.encodeInt16( falgs, data, offset+12 );
		
		ByteUtil.encodeInt16( windowSize, data, offset+14 );
		
		// Calculate checksum
		// Note: could also just ICMP6Message.calculateIcmp6Checksum( m.ipPacket ) after putting the packet together...
		byte[] checksumBuffer = new byte[60 + payloadSize];
		ByteUtil.copy( sourceAddressBuffer, sourceAddressOffset, checksumBuffer,  0, 16 );
		ByteUtil.copy(   destAddressBuffer,   destAddressOffset, checksumBuffer, 16, 16 );
		ByteUtil.encodeInt32( TCP_HEADER_SIZE + payloadSize, checksumBuffer, 32 ); // 'TCP Length'
		checksumBuffer[39] = TCP_PROTOCOL_NUMBER; // 'next header'
		ByteUtil.copy( data, offset, checksumBuffer, 40, 16 ); // src/dest port, seq/ack num, falgs, windowSize
		// Leave checksum and 'urgent pointer' zero
		// Assuming no options.
		ByteUtil.copy( payloadBuffer, payloadOffset, checksumBuffer, 60, payloadSize );
		long checksum = InternetChecksum.checksum(checksumBuffer);
		
		ByteUtil.encodeInt16( (short)checksum, data, offset+16 );
		
		return TCPMessage.parse( p );
	}

	
	public static TCPMessage parse( byte[] data, int offset, int size, IPPacket p ) {
		if( size < 20 ) return new TCPMessage( data, offset, size, p, "TCP message size must be >= 20, but is only "+size);
		
		TCPMessage m = new TCPMessage( data, offset, size, p );
		m.sourcePort = ByteUtil.decodeUInt16( data, offset+0 );
		m.destPort   = ByteUtil.decodeUInt16( data, offset+2 );
		m.sequenceNumber = ByteUtil.decodeInt32( data, offset+4 );
		m.ackNumber = ByteUtil.decodeInt32( data, offset+8 );
		int falgs = ByteUtil.decodeUInt16( data, offset+12 );
		m.flags = falgs & 0x1FF;
		int dataOffset = ((falgs >> 12) & 0xF) << 2;
		if( dataOffset >= 20 || dataOffset < size ) {
			m.optionsOffset = offset + 20;
			m.optionsSize = dataOffset - 20;
			m.payloadOffset = offset + dataOffset;
			m.payloadSize = size - dataOffset;
			m.wellFormed = true;
		} else {
			m.wellFormed = false;
			m.note = "Data offset ("+dataOffset+" bytes) is out of range";
		}
		m.checksum = ByteUtil.decodeUInt16( data, offset+16 );
		return m;
	}
	
	public static TCPMessage parse( IPPacket p ) {
		return parse( p.getBuffer(), p.getPayloadOffset(), p.getPayloadSize(), p );
	}
	
	public String toString() {
		return "TCP packet "+(wellFormed ? "(well-formed)" : "(malformed)")+
			" sourcePort="+sourcePort+
			" destPort="+destPort+
			" seqNum="+sequenceNumber+
			" ackNum="+ackNumber+
			" flags=0x"+Integer.toHexString(flags)+
			" checksum="+checksum+
			" payloadSize="+payloadSize;
			
	}
}
