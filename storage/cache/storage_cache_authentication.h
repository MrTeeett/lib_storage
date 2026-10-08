#pragma once

#include <QtCore/QByteArray>
#include <QtCore/QDataStream>
#include <QtCore/QMessageAuthenticationCode>
#include <openssl/crypto.h>
#include <optional>

namespace Storage::Cache {

inline QByteArray ValueAuthenticationCode(
		const QByteArray &secret,
		quint64 high,
		quint64 low,
		quint8 tag,
		const QByteArray &value) {
	const auto key = QMessageAuthenticationCode::hash(
		QByteArray("nx-cache-authentication-v1"),
		secret,
		QCryptographicHash::Sha256);
	auto metadata = QByteArray();
	QDataStream stream(&metadata, QIODevice::WriteOnly);
	stream.setVersion(QDataStream::Qt_5_1);
	stream << high << low << tag << quint64(value.size());
	QMessageAuthenticationCode mac(QCryptographicHash::Sha256, key);
	mac.addData(metadata);
	mac.addData(value);
	return mac.result();
}

inline QByteArray SealCacheValue(
		const QByteArray &secret,
		quint64 high,
		quint64 low,
		quint8 tag,
		const QByteArray &value) {
	return QByteArray("NXCACH\0\1", 8)
		+ ValueAuthenticationCode(secret, high, low, tag, value) + value;
}

inline std::optional<QByteArray> OpenCacheValue(
		const QByteArray &secret,
		quint64 high,
		quint64 low,
		quint8 tag,
		const QByteArray &blob) {
	if (blob.size() <= 40 || !blob.startsWith(QByteArray("NXCACH\0\1", 8))) {
		return {};
	}
	const auto value = blob.mid(40);
	const auto expected = ValueAuthenticationCode(secret, high, low, tag, value);
	return (CRYPTO_memcmp(blob.constData() + 8, expected.constData(), 32) == 0)
		? std::make_optional(value)
		: std::nullopt;
}

} // namespace Storage::Cache
