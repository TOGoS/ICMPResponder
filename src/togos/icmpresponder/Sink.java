package togos.icmpresponder;

public interface Sink<ItemClass>
{
	public void give( ItemClass p ) throws Exception;
}
