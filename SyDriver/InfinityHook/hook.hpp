#pragma once
#include "headers.hpp"
#include "defines.h"
namespace KHook
{
	// ��ʼ������
	bool Initialize(InfinityCallbackPtr ssdtCallBack);

	// ��ʼ���غ�������
	bool Start();

	// �������غ�������
	bool Stop();
}