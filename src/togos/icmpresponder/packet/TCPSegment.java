package togos.icmpresponder.packet;

import togos.blob.SimpleByteChunk;
import togos.icmpresponder.ByteUtil;
import togos.icmpresponder.InternetChecksum;
import togos.icmpresponder.SimpleSocketAddressPair;
import togos.icmpresponder.SocketAddressPair;
import togos.icmpresponder.tcp.TCPFlags;

public class TCPSegment extends SimpleByteChunk
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

	/* Note that these offsets are in *bytes* and are relative to the buffer,
	 * so are not the same as the numbers given in the packet. */ 

	public int optionsOffset = 0;
	public int optionsSize = 0;
	public int dataOffset = 0;
	public int dataSize = 0;
	
	public TCPSegment( byte[] data, int offset, int size, IPPacket p, String note ) {
		super( data, offset, size );
		this.ipPacket = p;
		this.wellFormed = false;
		this.note = note;
	}
	
	public TCPSegment( byte[] data, int offset, int size, IPPacket p ) {
		super( data, offset, size );
		this.ipPacket = p;
	};
	
	public TCPSegment( IPPacket p ) {
		this( p.getBuffer(), p.getPayloadOffset(), p.getPayloadSize(), p );
	}
	
	/**
	 * Under normal circumstances this should return the same thing
	 * as ICMP6Message.calculateIcmp6Checksum( m.ipPacket )
	 * 
	 * It is here as sort of a double-check for my own code and to
	 * make sure packets are properly formed.
	 */
	public static int calculateChecksum( TCPSegment m ) {
		byte[] checksumBuffer = new byte[60 + m.optionsSize + m.dataSize];
		// Not yet implemented for IP4 packets
		IP6Packet ip6p = (IP6Packet)m.ipPacket;
		ByteUtil.copy( ip6p.getBuffer(), ip6p.getSourceAddressOffset()       , checksumBuffer,  0, 16 );
		ByteUtil.copy( ip6p.getBuffer(), ip6p.getDestinationAddressOffset()  , checksumBuffer, 16, 16 );
		ByteUtil.encodeInt32( TCP_HEADER_SIZE + m.optionsSize + m.dataSize, checksumBuffer,     32 ); // 'TCP Length'
		ByteUtil.encodeInt32( TCP_PROTOCOL_NUMBER, checksumBuffer, 36 ); // 'next header'
		
		// A simpler way (what ICMP6Message.calculateIcmp6Checksum( m.ipPacket ) would do):
		// ByteUtil.copy( m.getBuffer(), m.getOffset(), checksumBuffer, 40, m.getSize() );
		
		ByteUtil.copy( m.getBuffer(), m.getOffset(), checksumBuffer, 40, 20 ); // src/dest port, seq/ack num, falgs, windowSize, checksum, and urgent pointer
		ByteUtil.copy( m.getBuffer(), m.optionsOffset, checksumBuffer, 60, m.optionsSize );
		ByteUtil.copy( m.getBuffer(), m.dataOffset, checksumBuffer, 60 + m.optionsSize, m.dataSize );
		
		return (int)InternetChecksum.checksum(checksumBuffer);
	}
	
	////
	
	public static TCPSegment createV6(
		byte[] sourceAddressBuffer, int sourceAddressOffset, int sourcePort,
		byte[] destAddressBuffer, int destAddressOffset, int destPort,
		int seqNum, int ackNum, int flags, int windowSize,
		byte[] dataBuffer, int dataOffset, int dataSize
	) {
		IP6Packet p = IP6Packet.create(
			sourceAddressBuffer, sourceAddressOffset,
			destAddressBuffer, destAddressOffset,
			TCP_PROTOCOL_NUMBER, 255, TCP_HEADER_SIZE + dataSize
		);
		byte[] buffer = p.getBuffer();
		int offset = p.getPayloadOffset();
		
		ByteUtil.encodeInt16( sourcePort, buffer, offset+0 );
		ByteUtil.encodeInt16( destPort, buffer, offset+2 );
		ByteUtil.encodeInt32( seqNum, buffer, offset+4 );
		ByteUtil.encodeInt32( ackNum, buffer, offset+8 );
		
		int dataOffsetWords = 5; // i.e. 20 bytes
		int falgs = (dataOffsetWords << 12) | (flags & 0x1F);
		ByteUtil.encodeInt16( falgs, buffer, offset+12 );
		
		ByteUtil.encodeInt16( windowSize, buffer, offset+14 );
		
		// Calculate checksum
		// Note: could also just ICMP6Message.calculateIcmp6Checksum( m.ipPacket ) after putting the packet together...
		byte[] checksumBuffer = new byte[60 + dataSize];
		ByteUtil.copy( sourceAddressBuffer, sourceAddressOffset, checksumBuffer,  0, 16 );
		ByteUtil.copy(   destAddressBuffer,   destAddressOffset, checksumBuffer, 16, 16 );
		ByteUtil.encodeInt32( TCP_HEADER_SIZE + dataSize, checksumBuffer, 32 ); // 'TCP Length'
		checksumBuffer[39] = TCP_PROTOCOL_NUMBER; // 'next header'
		ByteUtil.copy( buffer, offset, checksumBuffer, 40, 16 ); // src/dest port, seq/ack num, falgs, windowSize
		// Leave checksum and 'urgent pointer' zero
		// Assuming no options.
		ByteUtil.copy( dataBuffer, dataOffset, checksumBuffer, 60, dataSize );
		long checksum = InternetChecksum.checksum(checksumBuffer);
		
		ByteUtil.encodeInt16( (short)checksum, buffer, offset+16 );
		
		ByteUtil.copy( dataBuffer, dataOffset, buffer, offset+20, dataSize );
		
		return TCPSegment.parse( p );
	}
	
	public static TCPSegment createV6(
		byte[] sourceAddressBuffer,
		byte[] destAddressBuffer,
		int seqNum, int ackNum, int flags, int windowSize,
		byte[] dataBuffer, int dataOffset, int dataSize
	) {
		return createV6(
			sourceAddressBuffer, 0, sourceAddressBuffer.length,
			destAddressBuffer, 0, destAddressBuffer.length,
			seqNum, ackNum, flags, windowSize,
			dataBuffer, dataOffset, dataSize
		);
	}

	
	public static TCPSegment create(
		SocketAddressPair sap,
		int seqNum, int ackNum, int flags, int windowSize,
		byte[] dataBuffer, int dataOffset, int dataSize
	) {
		if( sap.getIpVersion() == 6 ) {
			return createV6(
				sap.getSourceAddressBuffer(), sap.getSourceAddressOffset(), sap.getSourcePort(),
				sap.getDestinationAddressBuffer(), sap.getDestinationAddressOffset(), sap.getDestinationPort(),
				seqNum, ackNum, flags, windowSize,
				dataBuffer, dataOffset, dataSize
			);
		} else {
			throw new RuntimeException("TCPSegment.createResponse only supports IPv6 for now!");
		}
	}
	
	////
	
	public static TCPSegment parse( byte[] buffer, int offset, int size, IPPacket p ) {
		if( size < 20 ) return new TCPSegment( buffer, offset, size, p, "TCP message size must be >= 20, but is only "+size);
		
		TCPSegment m = new TCPSegment( buffer, offset, size, p );
		m.sourcePort = ByteUtil.decodeUInt16( buffer, offset+0 );
		m.destPort   = ByteUtil.decodeUInt16( buffer, offset+2 );
		m.sequenceNumber = ByteUtil.decodeInt32( buffer, offset+4 );
		m.ackNumber = ByteUtil.decodeInt32( buffer, offset+8 );
		int falgs = ByteUtil.decodeUInt16( buffer, offset+12 );
		m.flags = falgs & 0xFFF;
		int dataOffset = ((falgs >> 12) & 0xF) << 2;
		if( dataOffset >= 20 || dataOffset < size ) {
			m.optionsOffset = offset + 20;
			m.optionsSize = dataOffset - 20;
			m.dataOffset = offset + dataOffset;
			m.dataSize = size - dataOffset;
			m.wellFormed = true;
		} else {
			m.wellFormed = false;
			m.note = "Data offset ("+dataOffset+" bytes) is out of range";
		}
		m.checksum = ByteUtil.decodeUInt16( buffer, offset+16 );
		return m;
	}
	
	public static TCPSegment parse( IPPacket p ) {
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
			" payloadSize="+dataSize;
	}
	
	public boolean hasFlag( int flag ) {
		return (flags & flag) == flag;
	}
	
	public boolean isSyn() { return hasFlag(TCPFlags.SYN); }
	public boolean isAck() { return hasFlag(TCPFlags.ACK); }
	public boolean isFin() { return hasFlag(TCPFlags.FIN); }
	public boolean hasData() { return dataSize > 0; }
	
	public int getSequenceDelta() {
		// TODO: does RST count as one, also?
		return dataSize + (isSyn() ? 1 : 0) + (isFin() ? 1 : 0);
	}
	
	//// SocketAddressPair
	
	public SocketAddressPair getSocketAddressPair() {
		byte[] buffer = ipPacket.getBuffer();
		return new SimpleSocketAddressPair(
			ipPacket.getIpVersion(),
			buffer, ipPacket.getSourceAddressOffset(), sourcePort,
			buffer, ipPacket.getDestinationAddressOffset(), destPort
		);
	}
	
	public SocketAddressPair getInverseAddressPair() {
		byte[] buffer = ipPacket.getBuffer();
		return new SimpleSocketAddressPair(
			ipPacket.getIpVersion(),
			buffer, ipPacket.getDestinationAddressOffset(), destPort,
			buffer, ipPacket.getSourceAddressOffset(), sourcePort
		);
	}
}
