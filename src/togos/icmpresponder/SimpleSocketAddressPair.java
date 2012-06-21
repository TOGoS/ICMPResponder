package togos.icmpresponder;

import togos.blob.ByteChunk;
import togos.blob.util.BlobUtil;

public class SimpleSocketAddressPair implements SocketAddressPair
{
	final int ipVersion;
	final byte[] sBuf, dBuf;
	final int sOff, sPort, dOff, dPort;
	
	public SimpleSocketAddressPair(
		int ipVersion,
		byte[] sBuf, int sOff, int sPort,
		byte[] dBuf, int dOff, int dPort
	) {
		this.ipVersion = ipVersion;
		this.sBuf = sBuf; this.sOff = sOff; this.sPort = sPort;
		this.dBuf = dBuf; this.dOff = dOff; this.dPort = dPort;
	}
	
	public SimpleSocketAddressPair(
		int ipVersion,
		ByteChunk sAddr, int sPort,
		ByteChunk dAddr, int dPort
	) {
		this( ipVersion,
			sAddr.getBuffer(), sAddr.getOffset(), sPort,
			dAddr.getBuffer(), dAddr.getOffset(), dPort );
	}
	
	public static SimpleSocketAddressPair inverse( SocketAddressPair sap ) {
		return new SimpleSocketAddressPair(
			sap.getIpVersion(),
			sap.getDestinationAddressBuffer(), sap.getDestinationAddressOffset(), sap.getDestinationPort(),
			sap.getSourceAddressBuffer(), sap.getSourceAddressOffset(), sap.getSourcePort()
		);
	}
	
	public int getIpVersion() {  return ipVersion;  }
	public byte[] getDestinationAddressBuffer() {  return dBuf;  }
	public int getDestinationAddressOffset() {  return dOff;  }
	public int getDestinationPort() {  return dPort;  }
	public byte[] getSourceAddressBuffer() {  return sBuf;  }
	public int getSourceAddressOffset() {  return sOff;  }
	public int getSourcePort() {  return sPort;  }
	
	public static int addressLength( int ipVersion ) {
		switch( ipVersion ) {
		case( 4 ): return 4;
		case( 6 ): return 16;
		default: throw new RuntimeException("Don't know address length for IP version "+ipVersion);
		}
	}
	
	public static int hashCode( SocketAddressPair p ) {
		int ipVersion = p.getIpVersion();
		int aLen = addressLength(ipVersion);
		int h = ipVersion;
		h = (h << 13) | (h >> 19);
		h += BlobUtil.hashCode( p.getSourceAddressBuffer(), p.getSourceAddressOffset(), aLen );
		h = (h << 13) | (h >> 19);
		h += BlobUtil.hashCode( p.getDestinationAddressBuffer(), p.getDestinationAddressOffset(), aLen );
		return h;
	}
	
	public static boolean equals( SocketAddressPair p1, SocketAddressPair p2 ) {
		int aLen = addressLength(p1.getIpVersion());
		return 
			p1.getIpVersion() == p2.getIpVersion() &&
			BlobUtil.equals( p1.getSourceAddressBuffer(), p1.getSourceAddressOffset(), p2.getSourceAddressBuffer(), p2.getSourceAddressOffset(), aLen ) &&
			BlobUtil.equals( p1.getDestinationAddressBuffer(), p1.getDestinationAddressOffset(), p2.getDestinationAddressBuffer(), p2.getDestinationAddressOffset(), aLen );
	}
	
	public int hashCode() {
		return hashCode(this);
	}
	
	public boolean equals( Object o ) {
		return (o instanceof SocketAddressPair) && equals( this, (SocketAddressPair)o );
	}
}
