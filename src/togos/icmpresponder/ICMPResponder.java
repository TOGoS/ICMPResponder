package togos.icmpresponder;

import java.io.IOException;
import java.io.PrintStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketAddress;

import togos.blob.ByteChunk;
import togos.blob.SimpleByteChunk;

/**
 * Demonstrates parsing IPv6 headers and ICMP echo requests and responding to
 * them. IP packets must be encapsulated in UDP packets and sent to the port
 * that ICMPResponder listens on, e.g. by TUN2UDP -tun -no-pi
 */
public class ICMPResponder
{
	static class ByteUtil {
		public static void copy( byte[] source, int sourceOffset, byte[] dest, int destOffset, int length ) {
			while( length > 0 ) {
				dest[destOffset++] = source[sourceOffset++];
				--length;
			}
		}
		
		public static void copy( ByteChunk source, byte[] dest, int destOffset ) {
			copy( source.getBuffer(), source.getOffset(), dest, destOffset, source.getSize() );
		}
		
		public static final void encodeInt32( int value, byte[] dest, int destOffset ) {
			dest[destOffset+0] = (byte)(value >> 24);
			dest[destOffset+1] = (byte)(value >> 16);
			dest[destOffset+2] = (byte)(value >>  8);
			dest[destOffset+3] = (byte)(value >>  0);
		}
		
		public static int decodeInt32( byte[] buffer, int offset ) {
			return
				((buffer[offset + 0]&0xFF) << 24) |
				((buffer[offset + 1]&0xFF) << 16) |
				((buffer[offset + 2]&0xFF) <<  8) |
				((buffer[offset + 3]&0xFF) <<  0);
		}
		
		public static int decodeInt16( byte[] buffer, int offset ) {
			return
				((buffer[offset + 0]&0xFF) << 8) |
				((buffer[offset + 1]&0xFF) << 0);
		}
		
		//// Functions for getting values but doing bounds-checking first ////
		
		/**
		 * Ensures that a buffer of length bufferSize can contain a sub-buffer
		 * of length valueSize at valueOffset. 
		 */
		protected static void ensureAllocated( int bufferSize, int valueOffset, int valueSize, String role ) {
			if( valueOffset < 0 ) {
				throw new IndexOutOfBoundsException( "Cannot read/write "+role+" ("+valueSize+" bytes at "+valueOffset+") because the offset is < 0!" );
			}
			if( valueOffset+valueSize > bufferSize ) {
				throw new IndexOutOfBoundsException( "Cannot read/write "+role+" ("+valueSize+" bytes at "+valueOffset+") because it is outside of allocated memory ("+bufferSize+" bytes)" );
			}
		}
				
		protected static int getInt32( byte[] chunk, int chunkOffset, int chunkLength, int valueOffset, String role ) {
			ensureAllocated( chunkLength, valueOffset, 4, role );
			return decodeInt32( chunk, chunkOffset+valueOffset );
		}
		
		protected static int getInt16( byte[] chunk, int chunkOffset, int chunkLength, int valueOffset, String role ) {
			ensureAllocated( chunkLength, valueOffset, 2, role );
			return decodeInt16( chunk, chunkOffset+valueOffset );
		}
		
		protected static int getInt8( byte[] chunk, int chunkOffset, int chunkLength, int valueOffset, String role ) {
			ensureAllocated( chunkLength, valueOffset, 1, role );
			return chunk[chunkOffset+valueOffset]&0xFF;
		}
	}
	
	static class PacketUtil {
		public static final int IP6_HEADER_SIZE = 40;
		public static final int ICMP_HEADER_SIZE = 8;
		
		public static int getIp6PayloadLength( byte[] packet, int packetOffset, int packetSize ) {
			return ByteUtil.getInt16( packet, packetOffset, packetSize, 4, "IP6 payload length" );
		}
		
		public static int getValidatedIp6PayloadLength( byte[] packet, int packetOffset, int packetSize ) {
			int len = getIp6PayloadLength(packet, packetOffset, packetSize);
			if( len < 0 ) throw new IndexOutOfBoundsException("Packet's payload length is < 0: "+len);
			if( len + 40 > packetSize ) throw new IndexOutOfBoundsException("Packet's payload length is too large for packet of size "+packetSize+": "+len);
			return len;
		}
		
		public static int getIpVersion( byte[] packet, int packetOffset, int packetSize ) {
			return (ByteUtil.getInt8( packet, packetOffset, packetSize, 0, "IP version" ) >> 4) & 0xF;
		}
		
		public static int getIp6TrafficClass( byte[] packet, int packetOffset ) {
			return (ByteUtil.decodeInt32( packet, packetOffset+0) >> 20) & 0xFF;
		}
		
		public static int getIp6ProtocolNumber( byte[] packet, int packetOffset, int packetSize ) {
			return ByteUtil.getInt8( packet, packetOffset, packetSize, 6, "IP6 next header / protocol number" );
		}
		
		public static void copyIp6SourceAddress( byte[] packet, int packetOffset, int packetSize, byte[] dest, int destOffset ) {
			ByteUtil.ensureAllocated( packetSize, 8, 16, "IP6 source address" );
			ByteUtil.copy( packet, packetOffset+8, dest, destOffset, 16);
		}
		
		public static void copyIp6DestinationAddress( byte[] packet, int packetOffset, int packetSize, byte[] dest, int destOffset ) {
			ByteUtil.ensureAllocated( packetSize, 24, 16, "IP6 destination address" );
			ByteUtil.copy( packet, packetOffset+24, dest, destOffset, 16);
		}
		
		public static int getIp6PayloadOffset( int packetOffset ) {
			return packetOffset + 40;
		}
		
		public static long calculateIcmp6Checksum( byte[] packet, int offset, int size ) {
			int payloadLength = getValidatedIp6PayloadLength( packet, offset, size );
			
			byte[] data = new byte[40+payloadLength];
			copyIp6SourceAddress(      packet, offset, size, data,  0 );
			copyIp6DestinationAddress( packet, offset, size, data, 16 );
			ByteUtil.encodeInt32(             payloadLength, data, 32 );
			ByteUtil.encodeInt32( getIp6ProtocolNumber( packet, offset, size ), data, 36 );
			ByteUtil.copy( packet, getIp6PayloadOffset(offset), data, 40, payloadLength );
			return InternetChecksum.checksum( data );
		}
		
		protected static void dumpIcmp6Data( byte[] icmpMessage, int offset, int size, PrintStream ps ) {
			ByteUtil.ensureAllocated( size, 0, ICMP_HEADER_SIZE, "ICMP header" );
			
			ps.println( "    ICMP message type: "+(icmpMessage[offset]&0xFF) );
			ps.println( "    ICMP code: "+(icmpMessage[offset+1]&0xFF) );
			ps.println( "    ICMP checksum: "+ByteUtil.decodeInt16( icmpMessage, offset+2 ) );
		}
		
		protected static void dumpIp6Packet( byte[] packet, int offset, int size, PrintStream ps ) {
			ByteUtil.ensureAllocated( size, 0, IP6_HEADER_SIZE, "IP6 header" );
			
			ps.println("IPv6 packet");
			ps.println("  from: "+AddressUtil.formatIp6Address(packet, 8));
			ps.println("  to:   "+AddressUtil.formatIp6Address(packet, 24));
			ps.println("  hoplimit: "+(packet[offset+7] & 0xFF));
			ps.println("  payload length: " + ByteUtil.decodeInt16(packet, offset+4) );
			ps.println("  traffic class: " + getIp6TrafficClass(packet, offset) );
			ps.println("  protocol number: " + getIp6ProtocolNumber(packet, offset, size) );
			
			switch( packet[offset+8] & 0xFF ) {
			case( 58 ):
				dumpIcmp6Data( packet, getIp6PayloadOffset(offset), getValidatedIp6PayloadLength(packet,offset,size), ps );
			}
			
			ps.println( "    calculated ICMPv6 checksum: "+calculateIcmp6Checksum(packet, offset, size) );
		}
		
		public static void dumpPacket( byte[] packet, int offset, int length, PrintStream ps ) {
			switch( (packet[offset+0] >> 4) & 0xF ) {
			case( 6 ): dumpIp6Packet( packet, offset, length, ps ); 
			}
		}
	}
	
	static class AddressUtil {
		public static String formatIp6Address( byte[] addy, int offset ) {
			int[] parts = new int[8];
			for( int i=0; i<8; ++i ) {
				parts[i] = ((addy[offset+i*2]&0xFF) << 8) | (addy[offset+i*2+1]&0xFF);
			}
			String rez = "";
			for( int i=0; i<8; ++i ) {
				if( i > 0 ) rez += ":";
				rez += Integer.toHexString(parts[i]);
			}
			return rez;
		}
	}
	
	/**
	 * A ByteChunk with methods for getting/setting parts
	 */
	static class StructuredByteChunk extends SimpleByteChunk {
		public StructuredByteChunk( byte[] data, int offset, int size ) {
			super( data, offset, size );
		}
		
		protected void ensureAllocated( int offset, int size, String role ) {
			if( offset+size > this.size ) {
				throw new IndexOutOfBoundsException( "Cannot read/write "+role+" ("+size+" bytes at "+offset+") because it is outside of allocated memory ("+this.size+" bytes)" );
			}
		}
		
		protected int getInt4( int offset, int shift, String role ) {
			ensureAllocated( offset, 1, role );
			return (byte)((buffer[this.offset+offset] >> shift) & 0xF); 
		}
		protected void setInt4( int offset, int shift, int value, String role ) {
			ensureAllocated( offset, 1, role );
			buffer[this.offset+offset] = (byte)(
				(buffer[this.offset+offset] & ~(0xF<<shift)) |
				((value&0xF)<<shift)
			);
		}
		
		protected int getInt8( int offset, String role ) {
			ensureAllocated( offset, 1, role );
			return buffer[this.offset+offset]&0xFF; 
		}
		protected void setInt8( int offset, int value, String role ) {
			ensureAllocated( offset, 1, role );
			buffer[this.offset+offset] = (byte)value;
		}
		
		protected int getInt12( int offset, int shift, String role ) {
			return (short)((getInt16( offset, role ) >> shift) & 0xFFF);
		}
		
		protected int getInt16( int offset, String role ) {
			ensureAllocated( offset, 4, role );
			int o = this.offset+offset;
			return
				((buffer[o + 0]&0xFF) <<  8) |
				((buffer[o + 1]&0xFF) <<  0);
		}
		protected void setInt16( int offset, int value, String role ) {
			ensureAllocated( offset, 4, role );
			int o = this.offset+offset;
			buffer[o+0] = (byte)(value >> 8);
			buffer[o+1] = (byte)(value >> 0);
		}
		
		protected int getInt32( int offset, String role ) {
			ensureAllocated( offset, 4, role );
			int o = this.offset+offset;
			return
				((buffer[o + 0]&0xFF) << 24) |
				((buffer[o + 1]&0xFF) << 16) |
				((buffer[o + 2]&0xFF) <<  8) |
				((buffer[o + 3]&0xFF) <<  0);
		}
		protected void setInt32( int offset, int value, String role ) {
			ensureAllocated( offset, 4, role );
			int o = this.offset+offset;
			buffer[o+0] = (byte)(value >> 24);
			buffer[o+1] = (byte)(value >> 16);
			buffer[o+2] = (byte)(value >>  8);
			buffer[o+3] = (byte)(value >>  0);
		}
		
		protected ByteChunk getSubChunk( int offset, int length, String role ) {
			ensureAllocated( offset, length, role );
			return new SimpleByteChunk( buffer, this.offset+offset, length );
		}
		
		protected void setBytes( byte[] src, int srcOffset, int destOffset, int length ) {
			destOffset += offset;
			while( length>0 ) {
				buffer[destOffset++] = src[srcOffset++];
				--length;
			}
		}
	}
	
	// Based on
	// http://support.novell.com/techcenter/articles/img/nc1999_0502.gif
	// http://routemyworld.com/wp-content/uploads/2009/01/ipv6header.png
	
	static abstract class IPPacket extends StructuredByteChunk {
		public IPPacket( byte[] data, int offset, int size ) {
			super( data, offset, size );
		}
		
		static byte getIpPacketVersion( byte[] buffer, int offset, int size ) {
			if( size < 1 ) return 0;
			return (byte)((buffer[offset] >> 4) & 0xF);
		}
		
		static IPPacket parse( byte[] buffer, int offset, int size ) {
			switch( getIpPacketVersion(buffer,offset,size) ) {
			case( 4 ): return new IP4Packet( buffer, offset, size );
			case( 6 ): return new IP6Packet( buffer, offset, size );
			}
			return null;
		}
		
		static IPPacket parse( ByteChunk c ) {
			return parse( c.getBuffer(), c.getOffset(), c.getSize() );
		}
		
		public int getIpVersion() {
			return getInt4(0, 4, "IP version");
		}
		
		public abstract int getProtocolNumber();
		public abstract int getHopLimit(); // a.k.a. TTL in IPv4
		public abstract ByteChunk getSourceAddress();
		public abstract ByteChunk getDestinationAddress();
		public abstract StructuredByteChunk getPayload();
	}
	
	static class IP4Packet extends IPPacket {
		public IP4Packet( byte[] data, int offset, int size ) {
			super( data, offset, size );
		}

		public int getIhl() {
			return getInt4(0, 0, "IHL");
		}
		
		public int getTypeOfservice() {
			return getInt8(1, "type of service");
		}
		
		public int getTotalLength() {
			return getInt16(2, "total IP4 packet length");
		}
		
		public int getIdentification() {
			return getInt16(4, "IP4 identification");
		}
		
		public int getFlags() {
			return getInt4(6, 4, "IP4 flags");
		}
		
		public int getFragmentOffset() {
			return getInt12(6, 0, "IP4 fragment offset");
		}
		
		public int getHopLimit() {
			return getInt8(8, "IP4 time-to-live / hop limit");
		}
		
		public int getProtocolNumber() {
			return getInt8(9, "IP4 protocol");
		}

		public int getHeaderChecksum() {
			return getInt16(10, "IP4 protocol");
		}
		
		public ByteChunk getSourceAddress() {
			return getSubChunk(12,4,"IP4 source address");
		}
		
		public ByteChunk getDestinationAddress() {
			return getSubChunk(16,4,"IP4 source address");
		}
		
		public StructuredByteChunk getPayload() {
			int len = getTotalLength();
			if( len < 20 || len > getSize() ) {
				throw new IndexOutOfBoundsException("Total length is out of range 20.."+getSize()+": "+len);
			}
			return new StructuredByteChunk( buffer, offset+20, len-20 );
		}
	}
	
	static class IP6Packet extends IPPacket {
		public IP6Packet( byte[] data, int offset, int size ) {
			super( data, offset, size );
		}
		
		public void initDefaults() {
			int trafficClass = 0;
			int flowLabel = 0;
			setInt32( 0, (6 << 28) | (trafficClass << 20) | (flowLabel), "IP6 version/class/flags" );
		}
		
		public int getTrafficClass() {
			return (getInt32(0, "IP6 version/class/flags") >> 20) & 0xFF;
		}
		public void setTrafficClass( int c ) {
			int vcf = getInt32(0, "IP6 version/class/flags");
			vcf = (vcf & 0xF00FFFFF) | ((c & 0xFF) << 20);
			setInt32( 0, vcf, "IP6 version/class/flags" );
		}
		
		// a.k.a. next header
		public int getProtocolNumber() {
			return getInt8(6, "IP6 next header type");
		}
		
		public int getHopLimit() {
			return getInt8(7, "IP6 hop limit");
		}
		
		public ByteChunk getSourceAddress() {
			return getSubChunk(8,16,"IP6 source address");
		}
		public void setSourceAddress( ByteChunk sourceAddress ) {
			setBytes( sourceAddress.getBuffer(), sourceAddress.getOffset(), 8, 16 );
		}
		
		public ByteChunk getDestinationAddress() {
			return getSubChunk(24,16,"IP4 source address");
		}
		public void setDestinationAddress( ByteChunk sourceAddress ) {
			setBytes( sourceAddress.getBuffer(), sourceAddress.getOffset(), 24, 16 );
		}
		
		public StructuredByteChunk getPayload() {
			int len = PacketUtil.getIp6PayloadLength( buffer, offset, size );
			if( len < 0 || len > (getSize()-40) ) {
				throw new IndexOutOfBoundsException("Payload length is out of range 0.."+(getSize()-40)+": "+len);
			}
			ensureAllocated( 40, len, "IP6 payload" );
			return new StructuredByteChunk( buffer, offset+40, len );
		}
	}
	
	/**
	 * The payload of an IP packet with protocol 1 or 58
	 */
	static class ICMPMessage extends StructuredByteChunk {
		public ICMPMessage( byte[] buffer, int offset, int size ) {
			super( buffer, offset, size );
		}
		
		public int getIcmpMessageType() {
			return getInt8(0, "ICMP message type");
		}
		
		public int getIcmpCode() {
			return getInt8(1, "ICMP code");
		}
		
		public int getIcmpChecksum() {
			return getInt16(2, "ICMP checksum");
		}
		
		public ByteChunk getIcmpMessageBody() {
			ensureAllocated(4, 0, "ICMP message body");
			return new SimpleByteChunk( buffer, offset+4, size-4 );
		}
	}
	
	interface PacketIO {
		public ByteChunk recv();
		public void send(ByteChunk c);
	}
	
	interface IPPacketIO {
		public IPPacket recv();
		public void send(IPPacket c);
	}
	
	static class DatagramPacketIO implements PacketIO {
		public static final int DEFAULT_MTU = 2048;
		
		DatagramSocket sock;
		int mtu;
		SocketAddress lastReceivedFrom;
		
		public DatagramPacketIO( DatagramSocket sock, int mtu ) {
			this.sock = sock;
			this.mtu = mtu;
		}
		public DatagramPacketIO( DatagramSocket sock ) {
			this( sock, DEFAULT_MTU );
		}
		
		public ByteChunk recv() {
			DatagramPacket p = new DatagramPacket(new byte[mtu], mtu);
			try {
				sock.receive(p);
				lastReceivedFrom = p.getSocketAddress();
			} catch( IOException e ) {
				throw new RuntimeException(e);
			}
			return new SimpleByteChunk(p.getData(), p.getOffset(), p.getLength());
		}
		
		public void send(ByteChunk c) {
			// If we don't know where to send it, just drop it.
			if( lastReceivedFrom == null ) return;
			
			DatagramPacket p = new DatagramPacket(c.getBuffer(), c.getOffset(), c.getSize());
			p.setSocketAddress(lastReceivedFrom);
			try {
				sock.send(p);
			} catch( IOException e ) {
				throw new RuntimeException(e);
			}
		}
	}
	
	static class IPPacketIOWrapper implements IPPacketIO {
		PacketIO pio;
		
		public IPPacketIOWrapper( PacketIO pio ) {
			this.pio = pio;
		}
		
		public IPPacket recv() {
			while( true ) {
				ByteChunk c = pio.recv();
				IPPacket p = IPPacket.parse(c);
				
				System.err.print( "Received packet: " );
				PacketUtil.dumpPacket(p.getBuffer(), p.getOffset(), p.getSize(), System.err);
				
				if( p != null ) return p;
			}
		}
		
		public void send(IPPacket p) {
			System.err.print( "Sending packet: " );
			PacketUtil.dumpPacket(p.getBuffer(), p.getOffset(), p.getSize(), System.err);
			pio.send(p);
		}
	}
	
	static class IPPacketHandler {
		protected final IPPacketIO responder;
		public IPPacketHandler( IPPacketIO responder ) {
			this.responder = responder;
		}
				
		protected IP6Packet createIcmpEchoResponse( IP6Packet pingPacket ) {
			byte[] data = new byte[pingPacket.getSize()];
			IP6Packet pong = new IP6Packet( data, 0, data.length );
			pong.setBytes( pingPacket.getBuffer(), pingPacket.getOffset(), 0, pingPacket.getSize());
			pong.initDefaults();
			pong.setSourceAddress( pingPacket.getDestinationAddress() );
			pong.setDestinationAddress( pingPacket.getSourceAddress() );
			pong.getPayload().setInt8(0, 129, "ICMP message type");
			pong.getPayload().setInt16(2, 0, "ICMP checksum");
			pong.getPayload().setInt16(2, (short)PacketUtil.calculateIcmp6Checksum(pong.getBuffer(), pong.getOffset(), pong.getSize()), "ICMP checksum");
			return pong;
		}
		
		protected void handleIcmp6Packet( IP6Packet p ) {
			ByteChunk payload = p.getPayload();
			ICMPMessage m = new ICMPMessage( payload.getBuffer(), payload.getOffset(), payload.getSize() );
			System.err.println("ICMP type="+m.getIcmpMessageType()+", code="+m.getIcmpCode()+", checksum="+m.getIcmpChecksum());
			switch( m.getIcmpMessageType() ) {
			case( 128 ): // Echo request
				responder.send( createIcmpEchoResponse(p) );
			}
		}
		
		public void handle( IPPacket p ) {
			switch( p.getIpVersion() ) {
			case( 4 ): break;
			case( 6 ):
				switch( p.getProtocolNumber() ) {
				case( 58 ): // ICMPv6
					handleIcmp6Packet( (IP6Packet)p ); break;
				}
				break;
			}
		}
	}
	
	public static void main( String[] args ) throws Exception {
		DatagramSocket s = new DatagramSocket(7777);
		DatagramPacketIO io = new DatagramPacketIO(s);
		IPPacketIOWrapper ipio = new IPPacketIOWrapper(io);
		IPPacketHandler h = new IPPacketHandler(ipio);
		IPPacket ipp;
		while( (ipp = ipio.recv()) != null ) {
			h.handle(ipp);
		}
	}
}
