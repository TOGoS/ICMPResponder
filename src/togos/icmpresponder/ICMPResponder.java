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
		
		public static void encodeInt16( int value, byte[] buffer, int offset ) {
			buffer[offset+0] = (byte)(value >> 8);
			buffer[offset+1] = (byte)(value >> 0);
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
		
		// Based on
		// http://support.novell.com/techcenter/articles/img/nc1999_0502.gif
		// http://routemyworld.com/wp-content/uploads/2009/01/ipv6header.png
		
		public static final int IP4_HEADER_SIZE = 20;
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
		
		public static int getIp6ProtocolNumber( byte[] packet, int packetOffset ) {
			return packet[packetOffset+6] & 0xFF;
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
			ByteUtil.encodeInt32( getIp6ProtocolNumber( packet, offset ), data, 36 );
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
			ps.println("  protocol number: " + getIp6ProtocolNumber(packet, offset) );
			
			switch( getIp6ProtocolNumber(packet, offset) ) {
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
	
	interface PacketIO {
		public ByteChunk recv();
		public void send(ByteChunk c);
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
	
	static class IPPacketIOWrapper implements PacketIO {
		PacketIO pio;
		
		public IPPacketIOWrapper( PacketIO pio ) {
			this.pio = pio;
		}
		
		public ByteChunk recv() {
			while( true ) {
				ByteChunk c = pio.recv();
				
				System.err.print( "Received packet: " );
				PacketUtil.dumpPacket(c.getBuffer(), c.getOffset(), c.getSize(), System.err);
				
				if( c != null ) return c;
			}
		}
		
		public void send(ByteChunk c) {
			System.err.print( "Sending packet: " );
			PacketUtil.dumpPacket(c.getBuffer(), c.getOffset(), c.getSize(), System.err);
			pio.send(c);
		}
	}
	
	static class IPPacketHandler {
		protected final PacketIO responder;
		public IPPacketHandler( PacketIO responder ) {
			this.responder = responder;
		}
				
		protected ByteChunk createIcmpEchoResponse( byte[] ping, int offset, int size ) {
			byte[] pong = new byte[size];
			
			ByteUtil.copy( ping, offset, pong, 0, size );

			int trafficClass = 0;
			int flowLabel = 0;
			ByteUtil.encodeInt32( (6 << 28) | (trafficClass << 20) | flowLabel, pong, 0 );
			ByteUtil.copy( ping, offset+8, pong, offset+24, 16 ); // Source address
			ByteUtil.copy( ping, offset+24, pong, offset+8, 16 ); // Dest address
			final int payloadOffset = PacketUtil.IP6_HEADER_SIZE;
			pong[payloadOffset + 0] = (byte)129; // ICMPv6 echo response 
			pong[payloadOffset + 1] =         0; // ICMPv6 code
			pong[payloadOffset + 2] =         0; // Cleared checksum
			pong[payloadOffset + 3] =         0; // Cleared checksum
			// Then calculate actual checksum
			int checksum = (int)PacketUtil.calculateIcmp6Checksum(pong, offset, size);
			ByteUtil.encodeInt16( checksum, pong, payloadOffset + 2 );
			return new SimpleByteChunk(pong);
		}
		
		protected void handleIcmp6Packet( byte[] packet, int offset, int size ) {
			switch( packet[offset+PacketUtil.IP6_HEADER_SIZE] & 0xFF ) {
			case( 128 ): // Echo request
				responder.send( createIcmpEchoResponse(packet, offset, size) );
				break;
			}
		}
		
		public void handleIp6( byte[] packet, int offset, int size ) {
			switch( PacketUtil.getIp6ProtocolNumber(packet, offset) ) {
			case( 58 ): // ICMPv6
				handleIcmp6Packet( packet, offset, size ); break;
			}
		}
		
		public void handle( byte[] packet, int offset, int size ) {
			if( size < PacketUtil.IP4_HEADER_SIZE ) {
				throw new IndexOutOfBoundsException("Packet smaller than IP4 header!");
			}
			switch( (packet[offset] >> 4) & 0xF ) {
			case( 4 ): break;
			case( 6 ): handleIp6( packet, offset, size ); break;
			}
		}
	}
	
	public static void main( String[] args ) throws Exception {
		DatagramSocket s = new DatagramSocket(7777);
		DatagramPacketIO io = new DatagramPacketIO(s);
		IPPacketIOWrapper ipio = new IPPacketIOWrapper(io);
		IPPacketHandler h = new IPPacketHandler(ipio);
		ByteChunk packet;
		while( (packet = ipio.recv()) != null ) {
			h.handle(packet.getBuffer(), packet.getOffset(), packet.getSize());
		}
	}
}
