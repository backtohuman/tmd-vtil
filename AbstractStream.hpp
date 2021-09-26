#pragma once

#include "insn.hpp"

class AbstractStream
{
protected:
	bool m_x86_64;

	AbstractStream(bool x86_64 = false);
	virtual ~AbstractStream();

public:
	bool is_x86_64() const
	{
		return this->m_x86_64;
	}

public:
	virtual bool isOpen() const = 0;
	virtual void close() = 0;
	virtual std::uint32_t read(void* buf, std::uint32_t size) = 0;
	virtual std::uint32_t write(const void* buf, std::uint32_t size) = 0;

	virtual unsigned long long pos() = 0;
	virtual void seek(unsigned long long pos) = 0;

	noncopyable_insn next();
};