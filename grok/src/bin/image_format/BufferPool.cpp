#include <BufferPool.h>

BufferPool::BufferPool() {}

BufferPool::~BufferPool()
{
	for(auto& p : pool)
		p.second.dealloc();
}

GrkSerializeBuf BufferPool::get(uint64_t len)
{
	for(auto iter = pool.begin(); iter != pool.end(); ++iter)
	{
		if(iter->second.allocLen >= len)
		{
			auto b = iter->second;
			b.dataLen = len;
			pool.erase(iter);
			// printf("Buffer pool get  %p\n", b.data);
			return b;
		}
	}
	GrkSerializeBuf rc;
	rc.alloc(len);

	return rc;
}
void BufferPool::put(GrkSerializeBuf b)
{
	assert(b.data);
	assert(pool.find(b.data) == pool.end());
	pool[b.data] = b;
}
