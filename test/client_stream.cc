// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/test/client_stream.h"

#include <utility>

#include "net/quic/core/quic_alarm.h"
#include "net/quic/core/quic_client_promised_info.h"
#include "net/quic/core/spdy_utils.h"
#include "net/quic/platform/api/quic_logging.h"
#include "net/spdy/core/spdy_protocol.h"
#include "net/tools/test/client_session.h"

using std::string;

namespace net {

QuicClientStream::QuicClientStream(QuicStreamId id,
                                           QuicClientSession* session)
    : QuicStream(id, session),
      content_length_(-1),
      response_code_(0),
      header_bytes_read_(0),
      header_bytes_written_(0),
      session_(session){}

QuicClientStream::~QuicClientStream() {}


void QuicClientStream::OnDataAvailable() {
  // For push streams, visitor will not be set until the rendezvous
  // between server promise and client request is complete.
//  if (visitor() == nullptr)
//    return;

  while (sequencer()->HasBytesToRead()) {
    struct iovec iov;
    if (sequencer()->GetReadableRegions(&iov, 1) == 0) {
      // No more data to read.
      break;
    }
    QUIC_DVLOG(1) << "Client processed " << iov.iov_len << " bytes for stream "
                  << id();
    data_.append(static_cast<char*>(iov.iov_base), iov.iov_len);

    if (content_length_ >= 0 &&
        data_.size() > static_cast<uint64_t>(content_length_)) {
      QUIC_DLOG(ERROR) << "Invalid content length (" << content_length_
                       << ") with data of size " << data_.size();
      Reset(QUIC_BAD_APPLICATION_PAYLOAD);
      return;
    }
    sequencer()->MarkConsumed(iov.iov_len);
  }
  if (sequencer()->IsClosed()) {
    OnFinRead();
  } else {
    sequencer()->SetUnblocked();
  }
}

size_t QuicClientStream::SendData(
                                         QuicStringPiece body,
                                         bool fin) {
  QuicConnection::ScopedPacketBundler bundler(
      session_->connection(), QuicConnection::SEND_ACK_IF_QUEUED);
  size_t bytes_sent = body.size();

  if (!body.empty()) {
    WriteOrBufferData(body, fin, nullptr);
  }


  return bytes_sent;
}

}  // namespace net

