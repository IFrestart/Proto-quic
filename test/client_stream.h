#ifndef NET_TOOLS_QUIC_QUIC_SPDY_CLIENT_STREAM_H_
#define NET_TOOLS_QUIC_QUIC_SPDY_CLIENT_STREAM_H_

#include <stddef.h>
#include <sys/types.h>
#include <string>

#include "base/macros.h"
#include "net/quic/core/quic_packets.h"
#include "net/quic/core/quic_stream.h"
#include "net/quic/platform/api/quic_string_piece.h"
#include "net/spdy/core/spdy_framer.h"

namespace net {

class QuicClientSession;

// All this does right now is send an SPDY request, and aggregate the
// SPDY response.
class QuicClientStream : public QuicStream {
 public:
  QuicClientStream(QuicStreamId id, QuicClientSession* session);
  ~QuicClientStream() override;

  using QuicStream::CloseWriteSide;
  // QuicStream implementation called by the session when there's data for us.
  void OnDataAvailable() override;

  // Serializes the headers and body, sends it to the server, and
  // returns the number of bytes sent.
  size_t SendData(QuicStringPiece body, bool fin);

  // Returns the response data.
  const std::string& data() { return data_; }

  // Returns whatever headers have been received for this stream.
  const SpdyHeaderBlock& response_headers() { return response_headers_; }

  const SpdyHeaderBlock& preliminary_headers() { return preliminary_headers_; }

  size_t header_bytes_read() const { return header_bytes_read_; }

  size_t header_bytes_written() const { return header_bytes_written_; }

  int response_code() const { return response_code_; }
  
  //void SetPriority(SpdyPriority priority);
 private:
  // The parsed headers received from the server.
  SpdyHeaderBlock response_headers_;

  // The parsed content-length, or -1 if none is specified.
  int64_t content_length_;
  int response_code_;
  std::string data_;
  size_t header_bytes_read_;
  size_t header_bytes_written_;

  QuicClientSession* session_;

  // These preliminary headers are used for the 100 Continue headers
  // that may arrive before the response headers when the request has
  // Expect: 100-continue.
  //bool has_preliminary_headers_;
  SpdyHeaderBlock preliminary_headers_;

  DISALLOW_COPY_AND_ASSIGN(QuicClientStream);
};

}  // namespace net

#endif 
