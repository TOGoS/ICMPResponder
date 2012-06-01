package togos.icmpresponder.tcp;

import java.io.IOException;
import java.io.OutputStream;
import java.util.HashMap;

import togos.icmpresponder.Sink;
import togos.icmpresponder.SocketAddressPair;
import togos.icmpresponder.packet.IPPacket;
import togos.icmpresponder.packet.TCPSegment;

public class ThreadyTCPServer
{
	interface ThreadyConnectionAdapter {
		public OutputStream accept( SocketAddressPair sap, OutputStream os );
	}
	
	final HashMap<SocketAddressPair,TCPSession> sessions = new HashMap();
	final Sink<TCPSegment> outgoingSegmentSink;
	
	ThreadyConnectionAdapter ca = new ThreadyConnectionAdapter() {
		public OutputStream accept( SocketAddressPair sap, final OutputStream os ) {
			return new OutputStream() {
				@Override public void write( byte[] b, int off, int len ) throws IOException {
					os.write( "You said:".getBytes() );
					os.write( b, off, len );
				}
				@Override public void write(int b) throws IOException {
					write( new byte[]{ (byte)b }, 0, 1 );
				};
				@Override public void close() throws IOException {
					os.close();
				}
			};
		}
	};
	
	public ThreadyTCPServer( final Sink<IPPacket> ipPacketSink ) {
		outgoingSegmentSink = new Sink<TCPSegment>() {
			public void give(TCPSegment p) throws Exception {
				ipPacketSink.give( p.ipPacket );
			}
		};
	}
	
	class TCPSessionOutputStream extends OutputStream 
	{
		public TCPSession tcpSession;
		@Override public void write( byte[] b, int off, int len ) throws IOException {
			try {
				tcpSession.sendBlocking( b, off, len );
			} catch( InterruptedException e ) {
				Thread.currentThread().interrupt();
				throw new IOException(e);
			} catch( Exception e ) {
				throw new IOException(e);
			}
		}
		@Override public void write(int b) throws IOException {
			write( new byte[]{ (byte)b }, 0, 1 );
		};
		@Override public void close() throws IOException {
			try {
				tcpSession.sendFin();
			} catch( InterruptedException e ) {
				Thread.currentThread().interrupt();
				throw new IOException(e);
			} catch( Exception e ) {
				throw new IOException(e);
			}
		}
	}
	
	public void handleTcpSegment( TCPSegment s ) throws Exception {
		SocketAddressPair sap = s.getSocketAddressPair();
		TCPSession tcpSession = null;
		if( s.isSyn() && !s.isAck() ) {
			TCPSessionOutputStream os = new TCPSessionOutputStream();
			OutputStream incoming = ca.accept(sap, os);
			if( incoming != null ) {
				tcpSession = new TCPSession( outgoingSegmentSink, incoming );
				os.tcpSession = tcpSession;
				sessions.put( sap, tcpSession );
			}
		} else {
			tcpSession = sessions.get(sap);
		}
		
		if( tcpSession != null ) tcpSession.handleIncomingSegment(s);
	}
}
