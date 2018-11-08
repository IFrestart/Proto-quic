#ifndef NET_TOOLS_QUIC_QUIC_SPDY_CLIENT_SESSION_H_
#define NET_TOOLS_QUIC_QUIC_SPDY_CLIENT_SESSION_H_

#include <memory>
#include <string>

#include "base/macros.h"
#include "net/quic/core/quic_crypto_client_stream.h"
#include "net/quic/core/quic_packets.h"
#include "net/quic/core/quic_spdy_client_session_base.h"
#include "net/tools/test/client_stream.h"

namespace net {

class QuicConnection;
class QuicServerId;

class QuicClientSession : public QuicSession ,
                     public QuicCryptoClientStream::ProofHandler{
 public:
  // Takes ownership of |connection|. Caller retains ownership of
  // |promised_by_url|.
  QuicClientSession(const QuicConfig& config,
                        QuicConnection* connection,
                        const QuicServerId& server_id,
                        QuicCryptoClientConfig* crypto_config);
  ~QuicClientSession() override;
  // Set up the QuicSpdyClientSession. Must be called prior to use.
  void Initialize() override;

  // QuicSession methods:
  QuicClientStream* CreateOutgoingDynamicStream(
      SpdyPriority priority) override;
  QuicClientStream* MaybeCreateOutgoingDynamicStream(
      SpdyPriority priority) override;
  QuicCryptoClientStreamBase* GetMutableCryptoStream() override;
  const QuicCryptoClientStreamBase* GetCryptoStream() const override;

  bool IsAuthorized(const std::string& authority);

  // Performs a crypto handshake with the server.
  virtual void CryptoConnect();

  // Returns the number of client hello messages that have been sent on the
  // crypto stream. If the handshake has completed then this is one greater
  // than the number of round-trips needed for the handshake.
  int GetNumSentClientHellos() const;

  int GetNumReceivedServerConfigUpdates() const;
  void OnProofValid(const QuicCryptoClientConfig::CachedState& cached) override;
  void OnProofVerifyDetailsAvailable(
      const ProofVerifyDetails& verify_details) override;
 protected:
  // QuicSession methods:
  QuicStream* CreateIncomingDynamicStream(QuicStreamId id)override ;
  // If an outgoing stream can be created, return true.
  bool ShouldCreateOutgoingDynamicStream() ;

  // If an incoming stream can be created, return true.
  bool ShouldCreateIncomingDynamicStream(QuicStreamId id);
  QuicStream* MaybeCreateIncomingDynamicStream(QuicStreamId id) override;
  std::unique_ptr<QuicStream> CreateStream(QuicStreamId id) override;

  // Create the crypto stream. Called by Initialize().
  virtual std::unique_ptr<QuicCryptoClientStreamBase> CreateQuicCryptoStream();

  // TODO(ckrasic) remove when
  // quic_reloadable_flag_quic_refactor_stream_creation is deprecated.
  // Unlike CreateOutgoingDynamicStream, which applies a bunch of sanity checks,
  // this simply returns a new QuicSpdyClientStream. This may be used by
  // subclasses which want to use a subclass of QuicSpdyClientStream for streams
  // but wish to use the sanity checks in CreateOutgoingDynamicStream.
  virtual std::unique_ptr<QuicClientStream> CreateClientStream();

  const QuicServerId& server_id() { return server_id_; }
  QuicCryptoClientConfig* crypto_config() { return crypto_config_; }

 private:
  std::unique_ptr<QuicCryptoClientStreamBase> crypto_stream_;
  QuicServerId server_id_;
  QuicCryptoClientConfig* crypto_config_;

  DISALLOW_COPY_AND_ASSIGN(QuicClientSession);
};

}  // namespace net

#endif  // NET_TOOLS_QUIC_QUIC_SPDY_CLIENT_SESSION_H_

