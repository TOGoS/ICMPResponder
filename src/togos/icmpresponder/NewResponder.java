package togos.icmpresponder;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketAddress;

import togos.icmpresponder.packet.ICMP6Message;
import togos.icmpresponder.packet.IPPacket;

public class NewResponder
{
	DatagramSocket dgs;
	public NewResponder( DatagramSocket dgs ) {
		this.dgs = dgs;
	}
	
	SocketAddress lastReceivedFrom = null;
	
	protected void handlePacket( IPPacket p ) {
		System.err.println("Got IPv"+p.getIpVersion()+" packet as "+p.getClass().getSimpleName());
		switch( p.getPayloadProtocolNumber() ) {
		case( 58 ):
			ICMP6Message m = ICMP6Message.parse( p );
			System.err.println("ICMP6 message");
			System.err.println("  Type: "+m.icmpMessageType );
			System.err.println("  Code: "+m.icmpMessageCode );
			System.err.println("  Checksum: "+m.icmpChecksum );
			System.err.println("  Payload size: "+m.getPayloadSize());
			break;
		}
	}
	
	public void run() throws IOException {
		byte[] recvBuffer = new byte[2048];
		DatagramPacket p = new DatagramPacket( recvBuffer, 2048 );
		dgs.receive(p);
		lastReceivedFrom = p.getSocketAddress();
		byte[] packetBuffer = new byte[p.getLength()];
		for( int i=packetBuffer.length-1; i>=0; --i ) {
			packetBuffer[i] = recvBuffer[i];
		}
		handlePacket( IPPacket.parse( packetBuffer, 0, packetBuffer.length ) );
	}
	
	public static void main( String[] args ) throws Exception {
		DatagramSocket s = new DatagramSocket(7777);
		new NewResponder(s).run();
	}
}
