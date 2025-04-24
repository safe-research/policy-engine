import chalk from 'chalk'
import { TransactionResponse } from 'ethers'

export function formatGas(gas: bigint): string {
  return gas.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',')
}

export async function logGasUsage(tx: TransactionResponse, description: string): Promise<void> {
  const receipt = await tx.wait()
  if (!receipt) {
    throw new Error('Could not get receipt')
  }
  // eslint-disable-next-line no-console
  console.log(
    chalk.cyan('⛽ Gas Used:'),
    chalk.yellow(description.padEnd(40)),
    chalk.green(`${formatGas(receipt.gasUsed)} gas`)
  )
}

export function logSection(title: string): void {
  // eslint-disable-next-line no-console
  console.log(chalk.blue('\n=== ' + title + ' ==='))
}

export async function logGasDiff(txFirst: TransactionResponse, txSecond: TransactionResponse): Promise<void> {
  const receiptFirst = await txFirst.wait()
  const receiptSecond = await txSecond.wait()

  if (!receiptFirst || !receiptSecond) {
    throw new Error('Could not get receipt')
  }

  const gasFirst = receiptFirst.gasUsed
  const gasSecond = receiptSecond.gasUsed

  const diff = gasSecond - gasFirst
  const percentage = (diff * 100n) / gasFirst
  // eslint-disable-next-line no-console
  console.log(
    chalk.magenta('📊 Gas Comparison:'),
    '\n',
    chalk.yellow('Without Guard:'.padEnd(20)),
    chalk.green(`${formatGas(gasFirst)} gas`),
    '\n',
    chalk.yellow('With Guard:'.padEnd(20)),
    chalk.green(`${formatGas(gasSecond)} gas`),
    '\n',
    chalk.yellow('Difference:'.padEnd(20)),
    chalk.red(`+${formatGas(diff)} gas`),
    chalk.gray(`(+${percentage}%)`)
  )
}
