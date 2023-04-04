#pragma once

#include "CtuCore.h"

namespace ctu {
	namespace net {
		template <typename T>
		struct packet_header
		{
			T id{};
			uint32_t size = 0;
		};

		template <typename T>
		struct packet
		{
			packet_header<T> header{};
			std::vector<uint8_t> body;

			// Returns the size of packet in bytes
			size_t size() const 
			{
				return body.size();
			}

			// Returns description of message
			friend std::ostream& operator << (std::ostream& os, const packet<T>& pkt)
			{
				os << "ID:" << int(pkt.header.id) << " Size:" << pkt.header.size;
				return os;
			}

			// Push data to packet
			template<typename DataType>
			friend packet<T>& operator << (packet<T>& pkt, const DataType& data)
			{
				// Check complexity
				static_assert(std::is_standard_layout<DataType>::value, "Data to complex.");

				// Size of vector
				size_t i = pkt.body.size();

				// Resize vector
				pkt.body.resize(pkt.body.size() + sizeof(DataType));

				// Copy from data to vector
				std::memcpy(pkt.body.data() + i, &data, sizeof(DataType));

				// Set size in header
				pkt.header.size = pkt.size();

				// Return to be reused
				return pkt;
			}

			// Pull data from packet
			template<typename DataType>
			friend packet<T>& operator >> (packet<T>& pkt, DataType& data)
			{
				// Check complexity
				static_assert(std::is_standard_layout<DataType>::value, "Data to complex.");

				// Location of data at end of vector
				size_t i = pkt.body.size() - sizeof(DataType);

				// Copy from vector to data
				std::memcpy(&data, pkt.body.data() + i, sizeof(DataType));

				// Shrink
				pkt.body.resize(i);

				// Set size in header
				pkt.header.size = pkt.size();

				// Return to be reused
				return pkt;
			}
		};
	}
}