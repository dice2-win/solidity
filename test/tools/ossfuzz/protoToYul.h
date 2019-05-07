/*
	This file is part of solidity.

	solidity is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	solidity is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with solidity.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <cstdint>
#include <cstddef>
#include <string>
#include <ostream>
#include <sstream>
#include <stack>
#include <set>
#include <vector>
#include <tuple>

#include <test/tools/ossfuzz/yulProto.pb.h>
#include <libdevcore/Common.h>
#include <libdevcore/FixedHash.h>

namespace yul
{
namespace test
{
namespace yul_fuzzer
{
class ProtoConverter
{
public:
	ProtoConverter()
	{
		// Tracks the number of live variables in function scope
		m_numLiveVars = 0;
		// Tracks the number of live variables in inner scope of a function
		m_numVarsPerScope.push(m_numLiveVars);
		// Tracks the number of nested for loops for loop index referencing
		m_numNestedForLoops = 0;
		m_inForScope.push(false);
		// Tracks the number of functions in program
		m_numFunctions = 0;
	}
	ProtoConverter(ProtoConverter const&) = delete;
	ProtoConverter(ProtoConverter&&) = delete;
	std::string programToString(Program const& _input);
	std::string protoToYul(uint8_t const* _data, size_t _size);

private:
	void visit(BinaryOp const&);
	void visit(Block const&);
	void visit(Literal const&);
	void visit(VarRef const&);
	void visit(Expression const&);
	void visit(VarDecl const&);
	void visit(MultiVarDecl const&);
	void visit(TypedVarDecl const&);
	void visit(UnaryOp const&);
	void visit(AssignmentStatement const&);
	void visit(MultiAssignment const&);
	void visit(IfStmt const&);
	void visit(StoreFunc const&);
	void visit(Statement const&);
	void visit(FunctionDefinition const&);
	void visit(ForStmt const&);
	void visit(CaseStmt const&);
	void visit(SwitchStmt const&);
	void visit(TernaryOp const&);
	void visit(NullaryOp const&);
	void visit(LogFunc const&);
	void visit(CopyFunc const&);
	void visit(ExtCodeCopy const&);
	void visit(StopInvalidStmt const&);
	void visit(RetRevStmt const&);
	void visit(SelfDestructStmt const&);
	void visit(TerminatingStmt const&);
	void visit(FunctionCallNoReturnVal const&);
	void visit(FunctionCallSingleReturnVal const&);
	void visit(FunctionCall const&);
	void visit(FunctionDefinitionNoReturnVal const&);
	void visit(FunctionDefinitionSingleReturnVal const&);
	void visit(FunctionDefinitionMultiReturnVal const&);
	void visit(Program const&);
	template <class T>
	void visit(google::protobuf::RepeatedPtrField<T> const& _repeated_field);
	void registerFunction(FunctionDefinition const&);
	void registerFunction(FunctionDefinitionNoReturnVal const&);
	void registerFunction(FunctionDefinitionSingleReturnVal const&);
	void registerFunction(FunctionDefinitionMultiReturnVal const&);

	std::string createHex(std::string const& _hexBytes) const;
	std::string createAlphaNum(std::string const& _strBytes) const;
	bool isCaseLiteralUnique(Literal const&);
	void createFunctionStub(int numInParams, int numOutParams);

	std::ostringstream m_output;
	std::stack<uint8_t> m_numVarsPerScope;
	int32_t m_numLiveVars;
	int32_t m_numNestedForLoops;
	std::stack<bool> m_inForScope;
	std::stack<std::set<dev::u256>> m_switchLiteralSetPerScope;
	int32_t m_numFunctions;
	// Vector whose index is a function reference, and whose value is the number of input parameters for that function
	std::vector<int> m_functionVecNoReturnValue;
	std::vector<int> m_functionVecSingeReturnValue;
	// Vector whose index is a function reference, and whose value is a pair <num input params, num output params> for
	// that function
	std::vector<std::pair<int,int>> m_functionVecMultiReturnValue;
	static int constexpr modInputParams = 5;
	static int constexpr modOutputParams = 5;
};
}
}
}
