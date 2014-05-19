package com.heluna.actor

import akka.actor.Actor
import com.heluna.model.{Greylist, Reject, Continue}
import java.util.Date
import com.typesafe.scalalogging.slf4j.Logging
import java.net.InetAddress
import com.heluna.filter._
import scala.concurrent.duration.FiniteDuration
import scala.concurrent.duration
import scala.concurrent.ExecutionContext.Implicits.global
import com.heluna.util.MailDropConfig

/**
 * Created with IntelliJ IDEA.
 * User: mark
 * Date: 4/30/13
 * Time: 9:20 PM
 */

class SenderCheckActor extends Actor with Logging {

	def receive = {

		case (inet: InetAddress, helo: String, from: String) => {
			// Flood control check
			IPFloodFilter.check(inet) match {
				case Reject(reason) => sender ! Reject(reason)
				case _ => {
					// DNS blacklist check
					DNSBLFilter.check(inet) match {
						case Reject(reason) => sender ! Reject(reason)
						case _ => {
							// SPF check
							SPFFilter.check(inet, helo, from) match {
								case Reject(reason) => sender ! Reject(reason)
								case _ => {
									// Senderbase check
									SenderbaseFilter.check(inet) match {
										case Reject(reason) => sender ! Reject(reason)
										case _ => sender ! Continue()
									}
								}
							}
						}
					}
				}
			}
		}

		case msg => {
			logger error "Got unknown message in SenderCheckActor: " + msg.toString + " " + self.path.name + " at " + new Date().getTime
			sender ! Continue()
		}

	}

}
