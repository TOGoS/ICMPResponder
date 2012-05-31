package togos.icmpresponder;

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
}
