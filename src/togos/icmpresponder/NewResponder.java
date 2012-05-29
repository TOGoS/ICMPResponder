package togos.icmpresponder;

import java.io.IOException;
import java.io.PrintStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketAddress;
import java.util.Random;

import togos.blob.ByteChunk;
import togos.icmpresponder.ICMPResponder.AddressUtil;
import togos.icmpresponder.packet.ICMP6Message;
import togos.icmpresponder.packet.IP6Packet;
import togos.icmpresponder.packet.IPPacket;
import togos.icmpresponder.packet.TCPMessage;

public class NewResponder
{
	DatagramSocket dgs;
	public NewResponder( DatagramSocket dgs ) {
		this.dgs = dgs;
	}
	
	SocketAddress lastReceivedFrom = null;
	
	protected void reply( byte[] buffer, int offset, int size ) throws IOException {
		dgs.send( new DatagramPacket(buffer, offset, size, lastReceivedFrom) );
	}
	
	protected void reply( ByteChunk bc ) throws IOException {
		System.err.println( "Sending to "+lastReceivedFrom);
		dumpPacket( bc, System.err );
		reply( bc.getBuffer(), bc.getOffset(), bc.getSize() );
	}
	
	protected void tryReply( ByteChunk bc ) {
		try {
			reply( bc );
		} catch( IOException e ) {
			System.err.println("Failed to send reply packet: "+e.getMessage());
		}
	}
	
	protected static void dumpPayload( IPPacket p, PrintStream out ) {
		switch( p.getPayloadProtocolNumber() ) {
		case( 58 ):
			ICMP6Message m = ICMP6Message.parse( p );
			out.println("  ICMP6 message");
			out.println("    Type: "+m.icmpMessageType );
			out.println("    Code: "+m.icmpMessageCode );
			out.println("    Payload size: "+m.getPayloadSize());
			out.println("    Checksum: "+m.icmpChecksum );
			if( m.ipPacket instanceof IP6Packet ) {
				out.println("    Calculated checksum: "+ICMP6Message.calculateIcmp6Checksum( (IP6Packet)m.ipPacket ));
			}
		case( 6 ):
			TCPMessage tm = TCPMessage.parse( p );
			out.println( "  "+tm.toString() );
			if( tm.ipPacket instanceof IP6Packet ) {
				out.println("    Calculated checksum: "+ICMP6Message.calculateIcmp6Checksum( (IP6Packet)tm.ipPacket ));
				out.println("    Calculated checksum 2: "+TCPMessage.calculateChecksum( tm ));
			}
		}
	}
	
	protected static void dumpPacket( ByteChunk c, PrintStream out ) {
		IPPacket p = IPPacket.parse( c.getBuffer(), c.getOffset(), c.getSize() );
		if( p instanceof IP6Packet ) {
			out.println("IP6 Packet");
			out.println("  From: "+AddressUtil.formatIp6Address(p.getBuffer(), p.getSourceAddressOffset()));
			out.println("  To:   "+AddressUtil.formatIp6Address(p.getBuffer(), p.getDestinationAddressOffset()));			
		} else {
			out.println("Some non-IP6 packet");
		}
		dumpPayload( p, out );
	}
	
	protected void handlePacket( IPPacket p ) {
		System.err.print("Received: ");
		dumpPacket( p, System.err );
		
		switch( p.getPayloadProtocolNumber() ) {
		case( 6 ):
			TCPMessage tm = TCPMessage.parse( p );
			
			if( (tm.flags & TCPFlags.RST) != 0 ) {
				System.err.println("Connection reset!");
				System.exit(1);
			}
			
			if( tm.ipPacket instanceof IP6Packet ) {
				IP6Packet ip6 = (IP6Packet)tm.ipPacket;
				
				switch( tm.flags ) {
				case( TCPFlags.SYN ):
					TCPMessage synAck = TCPMessage.createV6(
						ip6.buffer, ip6.getDestinationAddressOffset(), tm.destPort,
						ip6.buffer, ip6.getSourceAddressOffset(), tm.sourcePort,
						new Random().nextInt(), tm.sequenceNumber+1,
						TCPFlags.SYN|TCPFlags.ACK, 16384,
						ByteUtil.EMPTY_BTYE_ARRAY, 0, 0 );
					tryReply( synAck.ipPacket );
				}
			}
		case( 58 ):
			ICMP6Message m = ICMP6Message.parse( p );
			if( m.icmpMessageType == 128 ) {
				ICMP6Message reply = ICMP6Message.create(
					p.buffer, p.getDestinationAddressOffset(),
					p.buffer, p.getSourceAddressOffset(), 
					64, 129, 0, m.getBuffer(), m.getPayloadOffset(), m.getPayloadSize()
				);
				tryReply( reply.ipPacket );
			}
			
			break;
		}
	}
	
	public void run() throws IOException {
		byte[] recvBuffer = new byte[2048];
		while( true ) {
			DatagramPacket p = new DatagramPacket( recvBuffer, 2048 );
			dgs.receive(p);
			lastReceivedFrom = p.getSocketAddress();
			byte[] packetBuffer = new byte[p.getLength()];
			for( int i=packetBuffer.length-1; i>=0; --i ) {
				packetBuffer[i] = recvBuffer[i];
			}
			handlePacket( IPPacket.parse( packetBuffer, 0, packetBuffer.length ) );
		}
	}
	
	public static void main( String[] args ) throws Exception {
		DatagramSocket s = new DatagramSocket(7777);
		new NewResponder(s).run();
	}
}
