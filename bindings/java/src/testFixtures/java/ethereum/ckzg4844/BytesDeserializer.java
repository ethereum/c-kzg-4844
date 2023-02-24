package ethereum.ckzg4844;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.apache.tuweni.bytes.Bytes;

public class BytesDeserializer extends StdDeserializer<byte[]> {

  public BytesDeserializer() {
    this(null);
  }

  public BytesDeserializer(Class<?> vc) {
    super(vc);
  }

  @Override
  public byte[] deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException {
    JsonNode node = jp.getCodec().readTree(jp);
    if (node.isNull()) {
      return null;
    }
    if (node.isArray()) {
      List<byte[]> items = new ArrayList<>();
      for (final JsonNode itemNode : node) {
        items.add(Bytes.fromHexString(itemNode.asText()).toArray());
      }
      return TestUtils.flatten(items.toArray(byte[][]::new));
    }
    return Bytes.fromHexString(node.asText()).toArray();
  }
}
