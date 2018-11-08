#ifndef NET_TOOLS_QUIC_QUIC_SIMPLE_SERVER_STREAM_H_
#define NET_TOOLS_QUIC_QUIC_SIMPLE_SERVER_STREAM_H_

#include <string>

#include "base/macros.h"
#include "net/quic/core/quic_packets.h"
#include "net/quic/core/quic_stream.h"
#include "net/quic/platform/api/quic_string_piece.h"
#include "net/spdy/core/spdy_framer.h"

namespace net {

namespace test {
class QuicSimpleServerStreamPeer;
}  // namespace test

// All this does right now is aggregate data, and on fin, send an HTTP
// response.
class QuicServerSession;
class QuicServerStream : public QuicStream{
 public:
  QuicServerStream(QuicStreamId id,
                         QuicServerSession* session);
  ~QuicServerStream() override;
  // QuicStream implementation called by the sequencer when there is
  // data (or a FIN) to be read.
  void OnDataAvailable() override;
    void SetPriority(SpdyPriority priority);
 protected:
  SpdyHeaderBlock* request_headers() { return &request_headers_; }

  const std::string& body() { return body_; }

 private:
  friend class test::QuicSimpleServerStreamPeer;

  // The parsed headers received from the client.
  SpdyHeaderBlock request_headers_;
  int64_t content_length_;
  std::string body_;
  DISALLOW_COPY_AND_ASSIGN(QuicServerStream);
};

}  // namespace net

#endif  // NET_TOOLS_QUIC_QUIC_SIMPLE_SERVER_STREAM_H_

